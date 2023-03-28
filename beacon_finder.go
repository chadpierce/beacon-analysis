package main

/*	beacon_finder.go
 *	github.com/chadpierce/beacon_analysis
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
 *	Rudimentary MAD based data size analysis has been added.
 *
 *	Source code from RITA_pcap.ipynb was fed to a chat AI, then the bot was instructed to re-write
 *	the same logic in Go using only native libraries (some tweaking was required to get this working).
 *	Several additional features have been added manually.
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

// arguments
type Options struct {
	Help            bool
	InputFile       string
	OutputFile      string
	OutputDefault   bool
	Comma           string
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

// represents a row in the CSV file
type Record struct {
	Timestamp     time.Time
	Src           string
	Dst           string
	BytesSent     int
	BytesReceived int
}

// represents a group of records with the same source and destination
type GroupedRecord struct {
	Src           string
	Dst           string
	Times         []time.Time
	Deltas        []float64
	SentSizes     []int
	ReceivedSizes []int
}

// represents a grouped record with calculated scores
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

	opts := getOptions()

	// TODO check for single char input ...although anything past the first char gets ignored anyway?
	commaRune := []rune(opts.Comma)[0] // convert string to rune
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
	reader.Comma = commaRune // csv separator
	var records []Record

	log.Println("INFO: starting...")

	for {
		row, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatal(err) // TODO handle this differently?
			//log.Println("WARNING: ", err)  // maybe like this
			//continue
		}

		// skip rows where source or destination is "-"  // TODO make this optional?
		if row[srcCol] == "-" || row[dstCol] == "-" {
			continue
		}

		// parse timestamp from first column
		timestamp, err := time.Parse("2006-01-02-15:04:05", row[timeCol])
		if err != nil {
			//log.Fatal(err)  // throw warning and skip line - not sure if good idea?
			log.Println("WARNING: ", err)
			continue
		}

		// if NoBytes flag was passed, set to 0 - otherwise get values from csv
		var bytesSent int
		var bytesReceived int
		if opts.NoBytes {
			bytesSent = 0
			bytesReceived = 0
		} else {
			// parse bytes sent and received from their respective columns
			bytesSent, err = strconv.Atoi(row[bytesSentCol])
			if err != nil {
				log.Fatal(err) // TODO maybe warn but continue?
			}

			bytesReceived, err = strconv.Atoi(row[bytesReceivedCol])
			if err != nil {
				log.Fatal(err) // TODO maybe warn but continue?
			}
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

	// sort records by timestamp in ascending order
	sort.Slice(records, func(i, j int) bool {
		return records[i].Timestamp.Before(records[j].Timestamp)
	})

	// group records by source and destination, ignoring duplicate timestamps
	groupedRecords := groupRecords(records)

	// remove rows with popular destinations
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

			// weights for each sub-score
			skewWeight := opts.WeightSkew
			madmWeight := opts.WeightMadm
			connCountWeight := opts.WeightConnCount
			sizeWeight := opts.WeightSize
			if opts.NoBytes {
				sizeWeight = 0
			}

			scoreVal := (skewWeight*skewScoreVal + madmWeight*madmScoreVal + connCountWeight*connCountScoreVal +
				sizeWeight*sizeScore) / (skewWeight + madmWeight + connCountWeight + sizeWeight)
			// unweighted scoring:
			// scoreVal := (skewScoreVal + madmScoreVal + connCountScoreVal + sizeScore) / 4

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

	// sort scored records by score in descending order
	sort.Slice(scoredRecords, func(i, j int) bool {
		return scoredRecords[i].Score > scoredRecords[j].Score
	})

	// print scored records
	writeOutput(scoredRecords, opts.OutputFile, opts.NoBytes)
}

func isFlagPassed(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

func getOptions() Options {
	var opts Options
	flag.BoolVar(&opts.Help, "h", false, "display help")
	flag.StringVar(&opts.InputFile, "i", "", "input csv filename")
	flag.StringVar(&opts.OutputFile, "o", "", "write output to given filename")
	flag.BoolVar(&opts.OutputDefault, "O", false, "write output to inputfilename.out")
	flag.StringVar(&opts.Comma, "d", ",", "input csv delimiter (put in quotes: ';'")
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
	flag.BoolVar(&opts.NoBytes, "B", false, "do not use bytes sent/received in analysis")
	flag.BoolVar(&opts.Debug, "X", false, "[TODO] enable debug mode for extra output") // TODO
	flag.Parse()
	// check if -h flag is passed
	if opts.Help {
		fmt.Println("Usage of program:")
		flag.PrintDefaults()
		os.Exit(0)
	}
	if opts.InputFile == "" {
		log.Println("ERROR: Must supply input file (-i filename.csv)")
		os.Exit(0)
	}
	// if output file flag is passed, make sure it doesn't match input file
	if isFlagPassed("o") && isFlagPassed("O") {
		log.Println("ERROR: Cannot specify both -o and -O")
		os.Exit(0)
	}
	if isFlagPassed("o") {
		if opts.InputFile == opts.OutputFile {
			log.Println("ERROR: Input and Output files cannot have the same name")
			os.Exit(0)
		}
	}
	if opts.OutputDefault {
		outFile := opts.InputFile + ".out"
		log.Printf("INFO: output will be written to: %s\n", outFile)
		opts.OutputFile = outFile
	}
	// isFlagPassed is used to override defaults if presets -P or -D are used
	if opts.InputProxy && opts.InputDNS {
		log.Println("ERROR: cannot use both -P and -D")
		os.Exit(0)
	} else if opts.InputProxy && !opts.InputDNS {
		log.Println("INFO: Proxy mode selected")
		if !isFlagPassed("ct") {
			opts.ColumnTime = 0
		}
		if !isFlagPassed("cs") {
			opts.ColumnSource = 2
		}
		if !isFlagPassed("cd") {
			opts.ColumnDest = 7
		}
		if !isFlagPassed("cx") {
			opts.ColumnByteSent = 11
		}
		if !isFlagPassed("cr") {
			opts.ColumnByteRecv = 12
		}
		if !isFlagPassed("d") {
			opts.Comma = " "
		}
	} else if !opts.InputProxy && opts.InputDNS {
		log.Println("INFO: DNS mode selected")
		if !isFlagPassed("ct") {
			opts.ColumnTime = 0
		}
		if !isFlagPassed("cs") {
			opts.ColumnSource = 1
		}
		if !isFlagPassed("cd") {
			opts.ColumnDest = 2
		}
		if !isFlagPassed("cx") {
			opts.ColumnByteSent = -1
		}
		if !isFlagPassed("cr") {
			opts.ColumnByteRecv = -1
		}
		if !isFlagPassed("wz") {
			opts.WeightSize = 0
		}
		if !isFlagPassed("B") {
			opts.NoBytes = true
		}
	}

	return opts
}

// print scored records output, and write to file if needed
func writeOutput(scoredRecords []ScoredRecord, outputFile string, noBytes bool) {
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
		var output string
		if noBytes {
			output = fmt.Sprintf("%s -> %s | SCORE: %.3f | (skew: %.3f) (madm: %.3f) (connCount: %.3f) (size: -)\n",
				scoredRecord.Src, scoredRecord.Dst, scoredRecord.Score, scoredRecord.SkewScore, scoredRecord.MadmScore,
				scoredRecord.ConnCountScore)
		} else {
			output = fmt.Sprintf("%s -> %s | SCORE: %.3f | (skew: %.3f) (madm: %.3f) (connCount: %.3f) (size: %.3f)\n",
				scoredRecord.Src, scoredRecord.Dst, scoredRecord.Score, scoredRecord.SkewScore, scoredRecord.MadmScore,
				scoredRecord.ConnCountScore, scoredRecord.SizeScore)
		}
		// print to file if output filename exists, or print to console
		if outputFile != "" {
			_, err := file.WriteString(output)
			if err != nil {
				log.Fatal(err)
			}
		} else {
			fmt.Print(output)
		}
	}
	if outputFile != "" {
		log.Println("INFO: output to file: ", outputFile)
	} else {
		log.Println("INFO: finished")
	}

}

// groups records by source and destination, removing rows with duplicate timestamps,
// keeping the highest byte value.
// TODO revisit this methodology
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

		found := false
		for i, t := range groupedRecord.Times {
			if t == record.Timestamp {
				found = true
				if record.BytesSent > groupedRecord.SentSizes[i] {
					groupedRecord.SentSizes[i] = record.BytesSent
				}
				if record.BytesReceived > groupedRecord.ReceivedSizes[i] {
					groupedRecord.ReceivedSizes[i] = record.BytesReceived
				}
				break
			}
		}

		if !found {
			groupedRecord.Times = append(groupedRecord.Times, record.Timestamp)
			groupedRecord.SentSizes = append(groupedRecord.SentSizes, record.BytesSent)
			groupedRecord.ReceivedSizes = append(groupedRecord.ReceivedSizes, record.BytesReceived)
		}

		groupsMap[key] = groupedRecord
	}

	var groupedRecords []GroupedRecord
	for _, groupedRecord := range groupsMap {
		groupedRecords = append(groupedRecords, groupedRecord)
	}

	return groupedRecords
}

func removePopularDestinations(groupedRecords []GroupedRecord, maxDest int) []GroupedRecord {
	// create a map to keep track of the number of unique sources for each destination
	destinationCount := make(map[string]map[string]bool)

	// iterate over the groupedRecords to count the number of unique sources for each destination
	for _, record := range groupedRecords {
		if _, ok := destinationCount[record.Dst]; !ok {
			destinationCount[record.Dst] = make(map[string]bool)
		}
		destinationCount[record.Dst][record.Src] = true
	}

	// create a new slice to store the filtered groupedRecords
	var filteredGroupedRecords []GroupedRecord

	// iterate over the groupedRecords and only add records where the destination has maxDest or fewer unique sources
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

// calculates the median absolute deviation of the given slice of float64 values
func madm(deltas []float64) float64 {
	medianDelta := median(deltas)
	absDeltas := make([]float64, len(deltas))
	for i := range deltas {
		absDeltas[i] = math.Abs(deltas[i] - medianDelta)
	}
	return median(absDeltas)
}

// calculates the median of the given slice of float64 values
func median(deltas []float64) float64 {
	sort.Float64s(deltas)
	if len(deltas)%2 == 0 {
		return (deltas[len(deltas)/2-1] + deltas[len(deltas)/2]) / 2
	}
	return deltas[len(deltas)/2]
}

// calculates the median absolute deviation of the given slice of int values
func madmInt(sizes []int) float64 {
	floatSizes := make([]float64, len(sizes))
	for i := range sizes {
		floatSizes[i] = float64(sizes[i])
	}
	return madm(floatSizes)
}
