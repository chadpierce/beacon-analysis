package main

/*	beacon_finder.go
 *
 *	THIS SCRIPT IS PROVIDED "AS IS" WITH NO WARRANTIES OR GUARANTEES OF ANY
 *	KIND, INCLUDING BUT NOT LIMITED TO MERCHANTABILITY AND/OR FITNESS FOR A
 *	PARTICULAR PURPOSE. ALL RISKS OF DAMAGE REMAINS WITH THE USER, EVEN IF THE
 *	AUTHOR, SUPPLIER OR DISTRIBUTOR HAS BEEN ADVISED OF THE POSSIBILITY OF ANY
 *	SUCH DAMAGE. IF YOUR STATE DOES NOT PERMIT THE COMPLETE LIMITATION OF
 *	LIABILITY, THEN DO NOT DOWNLOAD OR USE THE SCRIPT. NO TECHNICAL SUPPORT
 *	WILL BE PROVIDED.
 *
 *	RITA-like beacon detection based on https://github.com/ppopiolek/c2-detection-using-statistical-analysis/blob/main/RITA_pcap.ipynb
 *	and https://github.com/Cyb3r-Monk/RITA-J/blob/main/C2%20Detection%20-%20HTTP.ipynb
 *
 *	- If beacon traffic ==> uniform distribution and small Median Absolute Deviation of time deltas
 *	- If user traffic ==> skewed distribution and large Median Absolute Deviation of time deltas
 *
 *	Rudimentary data size analysis has been added.
 *
 *	At the time of this writing, this code is completely written by Bing Chat AI.
 *	Source code from RITA_pcap was fed to the AI, and then it was instructed to re-write
 *	the same logic in go using only native libraries (some tweaking was required).
 *
 */

import (
	"encoding/csv"
	"fmt"
	"io"
	"log"
	"math"
	"os"
	"sort"
	"strconv"
	"sync"
	"time"
)

// Record represents a row in the CSV file
type Record struct {
	Timestamp     time.Time
	Src           string
	Dst           string
	BytesSent     int
	BytesReceived int
}

// GroupedRecord represents a group of records with the same source and destination
type GroupedRecord struct {
	Src           string
	Dst           string
	Times         []time.Time
	Deltas        []float64
	SentSizes     []int
	ReceivedSizes []int
}

// ScoredRecord represents a grouped record with calculated scores
type ScoredRecord struct {
	Src       string
	Dst       string
	Score     float64
	SizeScore float64
}

func main() {
	file, err := os.Open("proxy1.csv")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	var records []Record

	timeCol := 0           // column index for timestamp
	srcCol := 2            // column index for source
	dstCol := 7            // column index for destination
	bytesSentCol := 11     // column index for bytes_sent
	bytesReceivedCol := 12 // column index for bytes_received

	for {
		row, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatal(err)
		}

		// Skip rows where source or destination is "-"
		if row[srcCol] == "-" || row[dstCol] == "-" {
			continue
		}

		// Parse timestamp from first column
		timestamp, err := time.Parse("2006-01-02-15:04:05", row[timeCol])
		if err != nil {
			log.Fatal(err)
		}

		// Parse bytes sent and received from their respective columns
		bytesSent, err := strconv.Atoi(row[bytesSentCol])
		if err != nil {
			log.Fatal(err)
		}

		bytesReceived, err := strconv.Atoi(row[bytesReceivedCol])
		if err != nil {
			log.Fatal(err)
		}

		record := Record{
			Timestamp:     timestamp,
			Src:           row[srcCol],
			Dst:           row[dstCol],
			BytesSent:     bytesSent,
			BytesReceived: bytesReceived,
		}

		records = append(records, record)
	}

	// Sort records by timestamp in ascending order
	sort.Slice(records, func(i, j int) bool {
		return records[i].Timestamp.Before(records[j].Timestamp)
	})

	// Group records by source and destination
	groupedRecords := groupRecords(records)

	var scoredRecords []ScoredRecord

	var wg sync.WaitGroup

	scores := make(chan ScoredRecord, len(groupedRecords))

	for _, groupedRecord := range groupedRecords {
		if len(groupedRecord.Times) <= 36 {
			continue
		}

		wg.Add(1)

		go func(groupedRecord GroupedRecord) {
			defer wg.Done()

			deltas := make([]float64, len(groupedRecord.Times)-1)
			for i := 1; i < len(groupedRecord.Times); i++ {
				deltas[i-1] = groupedRecord.Times[i].Sub(groupedRecord.Times[i-1]).Seconds()
			}

			lowVal := percentile(deltas, 20)
			midVal := percentile(deltas, 50)
			highVal := percentile(deltas, 80)

			bowleyNumVal := lowVal + highVal - 2*midVal
			bowleyDenVal := highVal - lowVal

			skewVal := bowleyNumVal / bowleyDenVal
			if bowleyNumVal == 0 || midVal == lowVal || midVal == highVal {
				skewVal = 0
			}

			madmVal := madm(deltas)

			skewScoreVal := 1 - math.Abs(skewVal)
			madmScoreVal := 1 - madmVal/30
			if madmScoreVal < 0 {
				madmScoreVal = 0
			}

			connDivVal := groupedRecord.Times[len(groupedRecord.Times)-1].Sub(groupedRecord.Times[0]).Seconds()

			connCountScoreVal := 10 * float64(len(groupedRecord.Times)) / connDivVal

			if connCountScoreVal > 1 {
				connCountScoreVal = 1
			}

			scoreVal := (skewScoreVal + madmScoreVal + connCountScoreVal) / 3

			sentMadm := madmInt(groupedRecord.SentSizes)
			receivedMadm := madmInt(groupedRecord.ReceivedSizes)

			sizeScore := 1 - (sentMadm+receivedMadm)/2/1024
			if sizeScore < 0 {
				sizeScore = 0
			}

			scoredRecord := ScoredRecord{
				Src:       groupedRecord.Src,
				Dst:       groupedRecord.Dst,
				Score:     scoreVal,
				SizeScore: sizeScore,
			}

			scores <- scoredRecord
		}(groupedRecord)
	}

	wg.Wait()
	close(scores)

	for scoredRecord := range scores {
		scoredRecords = append(scoredRecords, scoredRecord)
	}

	// Sort scored records by score in descending order
	sort.Slice(scoredRecords, func(i, j int) bool {
		return scoredRecords[i].Score > scoredRecords[j].Score
	})

	// Print scored records
	for _, scoredRecord := range scoredRecords {
		fmt.Printf("%s %s %.3f %.3f\n", scoredRecord.Src, scoredRecord.Dst, scoredRecord.Score, scoredRecord.SizeScore)
	}
}

// groupRecords groups records by source and destination
func groupRecords(records []Record) []GroupedRecord {
	groupsMap := make(map[string]GroupedRecord)

	for _, record := range records {
		key := record.Src + " " + record.Dst

		groupedRecord, ok := groupsMap[key]

		if !ok {
			groupedRecord = GroupedRecord{
				Src:           record.Src,
				Dst:           record.Dst,
				Times:         []time.Time{},
				SentSizes:     []int{},
				ReceivedSizes: []int{},
			}
			groupsMap[key] = groupedRecord
		}

		groupedRecord.Times = append(groupedRecord.Times, record.Timestamp)
		groupedRecord.SentSizes = append(groupedRecord.SentSizes, record.BytesSent)
		groupedRecord.ReceivedSizes = append(groupedRecord.ReceivedSizes, record.BytesReceived)

		groupsMap[key] = groupedRecord
	}

	var groupedRecords []GroupedRecord
	for _, groupedRecord := range groupsMap {
		groupedRecords = append(groupedRecords, groupedRecord)
	}

	return groupedRecords
}

// percentile calculates the p-th percentile of the given slice of float64 values
func percentile(deltas []float64, p float64) float64 {
	sort.Float64s(deltas)
	index := p / 100 * float64(len(deltas))
	if index == float64(int(index)) {
		return (deltas[int(index)-1] + deltas[int(index)]) / 2
	}
	return deltas[int(index)]
}

// madm calculates the median absolute deviation of the given slice of float64 values
func madm(deltas []float64) float64 {
	medianDelta := median(deltas)
	absDeltas := make([]float64, len(deltas))
	for i := range deltas {
		absDeltas[i] = math.Abs(deltas[i] - medianDelta)
	}
	return median(absDeltas)
}

// median calculates the median of the given slice of float64 values
func median(deltas []float64) float64 {
	sort.Float64s(deltas)
	if len(deltas)%2 == 0 {
		return (deltas[len(deltas)/2-1] + deltas[len(deltas)/2]) / 2
	}
	return deltas[len(deltas)/2]
}

// madmInt calculates the median absolute deviation of the given slice of int values
func madmInt(sizes []int) float64 {
	floatSizes := make([]float64, len(sizes))
	for i := range sizes {
		floatSizes[i] = float64(sizes[i])
	}
	return madm(floatSizes)
}
