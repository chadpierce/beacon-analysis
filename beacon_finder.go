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
 *	Some additional features have been added manually.
 *
 *
 * 	This is documentation also written by Bing Chat:
 *
 * 	The calculation of each individual score can be tuned to account for variances in real-world traffic by adjusting the
 *		parameters used in their respective calculations.
 *
 * 	For example:
 *
 * 	- The skew score is calculated based on the skewness of the time deltas between consecutive records in a grouped record.
 *		You could adjust the percentiles used to calculate the skewness if desired.
 * 	- The MADM score is calculated based on the median absolute deviation from the median (MADM) of the time deltas between
 * 		consecutive records in a grouped record. You could adjust the scaling factor used to normalize the MADM value if desired.
 * 	- The connection count score is calculated based on the number of records in a grouped record divided by the time duration
 *		between the first and last record. You could adjust the scaling factor used to normalize this value if desired.
 * 	- The size score is calculated based on the median absolute deviation from the median (MADM) of the sent and received
 * 		sizes in a grouped record. You could adjust the scaling factor used to normalize these values if desired.
 *
 */

import (
	"encoding/csv"
	"flag"
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

// Defining arguments
type Options struct {
	Help            bool
	InputFile       string
	OutputFile      string
	ColumnTime      int
	ColumnSource    int
	ColumnDest      int
	ColumnByteRecv  int
	ColumnByteSent  int
	MaxSources      int
	MinScore        float64
	MinConnCount    int
	WeightSkew      float64
	WeightMadm      float64
	WeightConnCount float64
	WeightSize      float64
	InputProxy      bool
	InputDNS        bool
	NoBytes         bool
	Debug           bool
}

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
	Src            string
	Dst            string
	Score          float64
	SizeScore      float64
	SkewScore      float64
	MadmScore      float64
	ConnCountScore float64
}

func main() {
	var opts Options
	flag.BoolVar(&opts.Help, "h", false, "display help")
	flag.StringVar(&opts.InputFile, "i", "", "input csv filename")
	flag.StringVar(&opts.OutputFile, "o", "", "write output to given filename ")
	flag.IntVar(&opts.MinConnCount, "m", 36, "minimum number of connections threshold")
	flag.IntVar(&opts.MaxSources, "s", 5, "maximum number of sources for destination threshold")
	flag.Float64Var(&opts.MinScore, "S", .500, "minimum score threshold")
	flag.IntVar(&opts.ColumnTime, "ct", 0, "csv column for timestamp (default 0)")
	flag.IntVar(&opts.ColumnSource, "cs", 2, "csv column for source")
	flag.IntVar(&opts.ColumnDest, "cd", 7, "csv column for destination")
	flag.IntVar(&opts.ColumnByteRecv, "cr", 11, "csv column for bytes recevied")
	flag.IntVar(&opts.ColumnByteSent, "cx", 12, "csv column for bytes sent")
	flag.Float64Var(&opts.WeightSkew, "ws", 1.0, "weight value for skew score")
	flag.Float64Var(&opts.WeightMadm, "wm", 1.0, "weight value for MADM score")
	flag.Float64Var(&opts.WeightConnCount, "wc", 1.0, "weight value connection count score")
	flag.Float64Var(&opts.WeightSize, "wz", 1.0, "weight value for data size score")
	flag.BoolVar(&opts.InputProxy, "P", false, "use Proxy Log CSV Inputs")
	flag.BoolVar(&opts.InputDNS, "D", false, "use DNS Log CSV Inputs (no size analysis)")
	flag.BoolVar(&opts.InputDNS, "B", false, "do not use bytes sent/received in analysis")
	flag.BoolVar(&opts.InputDNS, "X", false, "enable debug mode for extra output (TODO)")
	flag.Parse()
	// Check if -h flag is provided
	if opts.Help {
		fmt.Println("Usage of program:")
		flag.PrintDefaults()
		os.Exit(0)
	}
	if opts.InputFile == "" {
		fmt.Println("Must supply input file (-i filename.csv)")
		os.Exit(0)
	}

	if opts.InputProxy && opts.InputDNS {
		fmt.Println("ERROR: cannot use both -P and -D")
		os.Exit(0)
	} else if opts.InputProxy && !opts.InputDNS {
		fmt.Println("INFO: Proxy mode selected")
		opts.ColumnTime = 0
		opts.ColumnSource = 2
		opts.ColumnDest = 7
		opts.ColumnByteSent = 11
		opts.ColumnByteRecv = 12
	} else if !opts.InputProxy && opts.InputDNS {
		fmt.Println("INFO: DNS mode selected")
		opts.ColumnTime = 0
		opts.ColumnSource = 1
		opts.ColumnDest = 2
		opts.ColumnByteSent = -1
		opts.ColumnByteRecv = -1
		opts.WeightSize = 0
		opts.NoBytes = true
	}

	timeCol := opts.ColumnTime
	srcCol := opts.ColumnSource
	dstCol := opts.ColumnDest
	bytesSentCol := opts.ColumnByteSent
	bytesReceivedCol := opts.ColumnByteRecv

	file, err := os.Open(opts.InputFile)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	var records []Record

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
	// Remove rows with Popular destinations
	groupedRecords = removePopularDestinations(groupedRecords, opts.MaxSources)

	var scoredRecords []ScoredRecord

	var wg sync.WaitGroup

	scores := make(chan ScoredRecord, len(groupedRecords))

	for _, groupedRecord := range groupedRecords {
		if len(groupedRecord.Times) <= opts.MinConnCount {
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

			sentMadm := madmInt(groupedRecord.SentSizes)
			receivedMadm := madmInt(groupedRecord.ReceivedSizes)

			sizeScore := 1 - (sentMadm+receivedMadm)/2/1024
			if sizeScore < 0 {
				sizeScore = 0
			}

			// weights for each score can be modified here
			skewWeight := opts.WeightSkew
			madmWeight := opts.WeightMadm
			connCountWeight := opts.WeightConnCount
			sizeWeight := opts.WeightSize

			scoreVal := (skewWeight*skewScoreVal + madmWeight*madmScoreVal + connCountWeight*connCountScoreVal +
				sizeWeight*sizeScore) / (skewWeight + madmWeight + connCountWeight + sizeWeight)
			//scoreVal := (skewScoreVal + madmScoreVal + connCountScoreVal + sizeScore) / 4

			scoredRecord := ScoredRecord{
				Src:            groupedRecord.Src,
				Dst:            groupedRecord.Dst,
				Score:          scoreVal,
				SizeScore:      sizeScore,
				SkewScore:      skewScoreVal,
				MadmScore:      madmScoreVal,
				ConnCountScore: connCountScoreVal,
			}

			// only return scored records above threshold
			if scoreVal > opts.MinScore {
				scores <- scoredRecord
			} else {
				return
			}

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
	writeOutput(scoredRecords, opts.OutputFile)
	// for _, scoredRecord := range scoredRecords {
	// 	fmt.Printf("%s -> %s | SCORE: %.3f | (skew: %.3f) (madm: %.3f) (connCount: %.3f) (size: %.3f)\n", scoredRecord.Src,
	//		scoredRecord.Dst, scoredRecord.Score, scoredRecord.SkewScore, scoredRecord.MadmScore, scoredRecord.ConnCountScore,
	//		scoredRecord.SizeScore)
	// }
}

// print scored recordsoutput, and write to file if needed
func writeOutput(scoredRecords []ScoredRecord, outputFile string) {
	var file *os.File
	var err error
	if outputFile != "" {
		file, err = os.Create(outputFile)
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()
	}

	for _, scoredRecord := range scoredRecords {
		output := fmt.Sprintf("%s -> %s | SCORE: %.3f | (skew: %.3f) (madm: %.3f) (connCount: %.3f) (size: %.3f)\n",
			scoredRecord.Src, scoredRecord.Dst, scoredRecord.Score, scoredRecord.SkewScore, scoredRecord.MadmScore,
			scoredRecord.ConnCountScore, scoredRecord.SizeScore)
		fmt.Print(output)
		if outputFile != "" {
			_, err := file.WriteString(output)
			if err != nil {
				log.Fatal(err)
			}
		}
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

func removePopularDestinations(groupedRecords []GroupedRecord, maxDest int) []GroupedRecord {
	// Create a map to keep track of the number of unique sources for each destination
	destinationCount := make(map[string]map[string]bool)

	// Iterate over the groupedRecords to count the number of unique sources for each destination
	for _, record := range groupedRecords {
		if _, ok := destinationCount[record.Dst]; !ok {
			destinationCount[record.Dst] = make(map[string]bool)
		}
		destinationCount[record.Dst][record.Src] = true
	}

	// Create a new slice to store the filtered groupedRecords
	var filteredGroupedRecords []GroupedRecord

	// Iterate over the groupedRecords and only add records where the destination has 5 or fewer unique sources
	for _, record := range groupedRecords {
		if len(destinationCount[record.Dst]) <= maxDest {
			filteredGroupedRecords = append(filteredGroupedRecords, record)
		}
	}
	return filteredGroupedRecords
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
