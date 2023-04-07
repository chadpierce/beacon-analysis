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
 *	Go based RITA-like beacon detection inspired by RITA itself:
 *	 - https://github.com/activecm/rita,
 * 	Along with the following repos:
 * 	- https://github.com/ppopiolek/c2-detection-using-statistical-analysis/blob/main/RITA_pcap.ipynb
 *	- https://github.com/Cyb3r-Monk/RITA-J/blob/main/C2%20Detection%20-%20HTTP.ipynb
 *
 *	- If beacon traffic ==> uniform distribution and small Median Absolute Deviation of time deltas
 *	- If user traffic ==> skewed distribution and large Median Absolute Deviation of time deltas
 *
 * 	TODO documentation
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
	"strings"
	"sync"
	"time"
)

// arguments
type Options struct {
	Help           bool
	InputFile      string
	OutputFile     string
	OutputDefault  bool
	Comma          string
	TimeFormat     string
	ColumnTime     int
	ColumnSource   int
	ColumnDest     int
	ColumnByteRecv int
	ColumnByteSent int
	ColumnMethod   int
	ColumnPort     int
	MaxSources     int
	MinScore       float64
	MinConnCount   int
	WeightTime     float64
	WeightData     float64
	WeightTSSkew   float64
	WeightTSMadm   float64
	WeightTSConn   float64
	WeightDSSkew   float64
	WeightDSMadm   float64
	WeightDSSmall  float64
	InputProxy     bool
	InputDNS       bool
	NoBytes        bool
	Caseness       bool
	MinDuration    float64
	TuneSmallness  float64
	Debug          bool
}

// represents a row in the CSV file
type Record struct {
	Timestamp     time.Time
	Src           string
	Dst           string
	Port          int
	Method        string
	BytesSent     int
	BytesReceived int
}

// represents a group of records with the same source and destination
type GroupedRecord struct {
	Src           string
	Dst           string
	Port          int
	Method        string
	Times         []time.Time
	Deltas        []float64
	SentSizes     []int
	ReceivedSizes []int
}

// represents a grouped record with calculated scores
type ScoredRecord struct {
	Src      string
	Dst      string
	Port     int
	Method   string
	Duration float64
	Score    float64
	DSScore  float64
	TSScore  float64
	DSSkew   float64
	DSMadm   float64
	DSSmall  float64
	TSSkew   float64
	TSMadm   float64
	TSConn   float64
}

func main() {

	opts := getOptions()
	isPort := false
	isMethod := false
	// TODO check for single char input ...although anything past the first char gets ignored anyway?
	commaRune := []rune(opts.Comma)[0] // convert string to rune
	timeCol := opts.ColumnTime
	srcCol := opts.ColumnSource
	dstCol := opts.ColumnDest
	bytesSentCol := opts.ColumnByteSent
	bytesReceivedCol := opts.ColumnByteRecv
	methodCol := opts.ColumnMethod
	portCol := opts.ColumnPort
	if methodCol != -1 {
		isMethod = true
	}
	if portCol != -1 {
		isPort = true
	}

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

		// parse timestamp format
		timeFmtStr := opts.TimeFormat
		timestamp, err := time.Parse(timeFmtStr, row[timeCol])
		if err != nil {
			log.Fatal(err) // throw warning and skip line? - not sure if good idea?
			// INPROG - add prompt to continue after error?
			// otherwise an error may be thrown for every line
			//log.Println("WARNING: ", err)
			//continue
		}

		// //for testing, uses epoch time
		// //>go run beacon_finder.go -ct 0 -cs 1 -cd 2 -cx 3 -cr 4 -i http-dataset2.log -d " " -O
		// //timestampStr := "1371601525.249082"
		// timestampStr := row[timeCol]
		// secs, err := strconv.ParseFloat(timestampStr, 64)
		// if err != nil {
		// 	// handle error
		// }
		// timestamp := time.Unix(int64(secs), int64((secs-math.Floor(secs))*1e9))

		method := ""
		if isMethod {
			method = row[methodCol]
		}
		port := 0
		if isPort {
			port, err = strconv.Atoi(row[portCol])
			if err != nil {
				log.Fatal(err)
			}
		}

		// if NoBytes flag was passed, set to 0 - otherwise get values from csv
		// only bytes sent are considered
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
			Port:          port,
			Method:        method,
			BytesSent:     bytesSent,
			BytesReceived: bytesReceived,
		}

		records = append(records, record)
	}

	// sort records by timestamp in ascending order
	sort.Slice(records, func(i, j int) bool {
		return records[i].Timestamp.Before(records[j].Timestamp)
	})

	// normalize src and dst caseness, disable with '-nocase' flag
	if !opts.Caseness {
		for i := range records {
			records[i].NormalizeChars()
		}
	}

	// group records by source and destination (and port/method if chosen), ignoring duplicate timestamps
	groupedRecords := groupRecords(records, isPort, isMethod)

	log.Println("cleaned records: ", len(groupedRecords))

	// remove rows with popular destinations
	groupedRecords = removePopularDestinations(groupedRecords, opts.MaxSources)

	//log.Println("cleaned records: ", len(groupedRecords))

	var scoredRecords []ScoredRecord

	var wg sync.WaitGroup

	scores := make(chan ScoredRecord, len(groupedRecords))

	for _, groupedRecord := range groupedRecords {
		if len(groupedRecord.Times) <= opts.MinConnCount {
			continue
		}
		if (groupedRecord.Times[len(groupedRecord.Times)-1].Sub(groupedRecord.Times[0]).Seconds() / 60 / 60) < opts.MinDuration {
			continue
		}
		wg.Add(1)

		go func(groupedRecord GroupedRecord) {
			defer wg.Done()

			// time based scoring
			tsDeltas := make([]float64, len(groupedRecord.Times)-1)
			for i := 1; i < len(groupedRecord.Times); i++ {
				tsDeltas[i-1] = groupedRecord.Times[i].Sub(groupedRecord.Times[i-1]).Seconds()
			}

			tsLowVal := percentile(tsDeltas, 20)
			tsMidVal := percentile(tsDeltas, 50)
			tsHighVal := percentile(tsDeltas, 80)

			hoursSesssionDur := groupedRecord.Times[len(groupedRecord.Times)-1].Sub(groupedRecord.Times[0]).Seconds() / 60 / 60

			tsBowleyNumVal := tsLowVal + tsHighVal - 2*tsMidVal
			tsBowleyDenVal := tsHighVal - tsLowVal

			tsSkewVal := tsBowleyNumVal / tsBowleyDenVal
			if tsBowleyNumVal == 0 || tsMidVal == tsLowVal || tsMidVal == tsHighVal {
				tsSkewVal = 0
			}

			// time delta score calculation
			tsSkewScore := 1 - math.Abs(tsSkewVal)

			tsMadmVal := madmFloat(tsDeltas)
			// If jitter is greater than 30 seconds, set madm score to 0
			// TODO TUNING
			tsMadmScore := 1 - tsMadmVal/30
			if tsMadmScore < 0 {
				tsMadmScore = 0
			}

			// num of connections scoring
			// TODO TUNING 90 value could use tuning?
			tsConnDivVal := groupedRecord.Times[len(groupedRecord.Times)-1].Sub(groupedRecord.Times[0]).Seconds() / 90

			tsConnCountScore := 10 * float64(len(groupedRecord.Times)) / tsConnDivVal
			if tsConnCountScore > 1 {
				tsConnCountScore = 1
			}

			// data based scoring
			// only bytes sent are considered
			dsSentMadm := madmInt(groupedRecord.SentSizes)
			//receivedMadm := madmInt(groupedRecord.ReceivedSizes)

			dsSizeScore := 1 - dsSentMadm/1024

			if dsSizeScore < 0 {
				dsSizeScore = 0
			}

			// convert to floats beforeing passing to percentile()
			var floatSizes []float64
			for _, s := range groupedRecord.SentSizes {
				floatSizes = append(floatSizes, float64(s))
			}
			dsLowVal := percentile(floatSizes, 20.0)
			dsMidVal := percentile(floatSizes, 50.0)
			dsHighVal := percentile(floatSizes, 80.0)

			//fmt.Printf("DEBUG ds: %v %v %v\n", dsLowVal, dsMidVal, dsHighVal)

			dsBowleyNumVal := dsLowVal + dsHighVal - 2*dsMidVal
			dsBowleyDenVal := dsHighVal - dsLowVal

			dsSkewVal := dsBowleyNumVal / dsBowleyDenVal
			if dsBowleyNumVal == 0 || dsMidVal == dsLowVal || dsMidVal == dsHighVal {
				dsSkewVal = 0
			}

			dsSkewScore := 1 - math.Abs(dsSkewVal)

			// if jitter over 128 bytes, score is zero
			// TODO TUNING
			dsMadmScore := 1.0 - (dsSizeScore / 128.0)
			if dsMadmScore < 0 {
				dsMadmScore = 0
			}
			// looking for low data sent values
			// a higher value (default 8192) is less sensitive
			// TODO TUNING
			dsSmallnessScore := 1.0 - (dsMidVal / opts.TuneSmallness) //8192.0)
			if dsSmallnessScore < 0 {
				dsSmallnessScore = 0
			}

			/* LEGACY SCORING SYSTEM
			// weights for each sub-score
			skewWeight := opts.WeightSkew
			madmWeight := opts.WeightMadm
			connCountWeight := opts.WeightConnCount
			sizeWeight := opts.WeightSize
			if opts.NoBytes {
				sizeWeight = 0
			}

			scoreVal := (skewWeight*tsSkewScoreVal + madmWeight*tsMadmScore + connCountWeight*tsConnCountScore +
				sizeWeight*dsSizeScore) / (skewWeight + madmWeight + connCountWeight + sizeWeight)
			// unweighted scoring:
			// scoreVal := (skewScoreVal + madmScoreVal + connCountScoreVal + sizeScore) / 4
			*/

			// weights for each sub-score
			timeWeight := opts.WeightTime
			dataWeight := opts.WeightData
			tsSkewWeight := opts.WeightTSSkew
			tsMadmWeight := opts.WeightTSMadm
			tsConnWeight := opts.WeightTSConn
			dsSkewWeight := opts.WeightDSSkew
			dsMadmWeight := opts.WeightDSMadm
			dsSmallWeight := opts.WeightDSSmall
			if opts.NoBytes {
				dataWeight = 0
			}

			// Final Scoring, weighed
			tsScore := ((tsSkewWeight*tsSkewScore + tsMadmWeight*tsMadmScore + tsConnWeight*tsConnCountScore) / (tsSkewWeight + tsMadmWeight + tsConnWeight))   // * 1000) / 1000
			dsScore := ((dsSkewWeight*dsSkewScore + dsMadmWeight*dsMadmScore + dsSmallWeight*dsSmallnessScore) / (dsSkewWeight + dsMadmWeight + dsSmallWeight)) // * 1000) / 1000

			scoreVal := (timeWeight*tsScore + dataWeight*dsScore) / (timeWeight + dataWeight)

			/*
				// Final Scoring, not weighed
				dsScore := (((dsSkewScore + dsMadmScore + dsSmallnessScore) / 3.0) * 1000) / 1000
				tsScore := (((tsSkewScore + tsMadmScore + tsConnCountScore) / 3.0) * 1000) / 1000
				scoreVal := (dsScore + tsScore) / 2

				// DEBUG
				testdsScore := (dsSkewScore + dsMadmScore + dsSmallnessScore) / 3.0 //) * 1000) / 1000
				testtsScore := (tsSkewScore + tsMadmScore + tsConnCountScore) / 3.0 //) * 1000) / 1000
				testscoreVal := (testdsScore + testtsScore) / 2
				fmt.Printf("TEST score %v ts %v ds %v \n", testscoreVal, testtsScore, testdsScore)
			*/

			scoredRecord := ScoredRecord{
				Src:      groupedRecord.Src,
				Dst:      groupedRecord.Dst,
				Port:     groupedRecord.Port,
				Method:   groupedRecord.Method,
				Duration: hoursSesssionDur,
				Score:    scoreVal,
				DSScore:  dsScore,
				TSScore:  tsScore,
				DSSkew:   dsSkewScore,
				DSMadm:   dsMadmScore,
				DSSmall:  dsSmallnessScore,
				TSSkew:   tsSkewScore,
				TSMadm:   tsMadmScore,
				TSConn:   tsConnCountScore,
			}

			// only return scored records above threshold
			// unless debug is enabled, then print all
			if opts.Debug {
				scores <- scoredRecord
			} else {
				if scoreVal > opts.MinScore {
					scores <- scoredRecord
				} else {
					return
				}
			}
		}(groupedRecord)
	}

	wg.Wait()
	close(scores)

	log.Println("scored records: ", len(scoredRecords))

	for scoredRecord := range scores {
		scoredRecords = append(scoredRecords, scoredRecord)
	}

	// sort scored records by score in descending order
	sort.Slice(scoredRecords, func(i, j int) bool {
		return scoredRecords[i].Score > scoredRecords[j].Score
	})

	// print scored records
	writeOutput(scoredRecords, opts.OutputFile, opts.NoBytes, isPort, isMethod)
}

// normalize character caseness for usernames, domains, etc
func (r *Record) NormalizeChars() {
	r.Src = strings.ToLower(r.Src)
	r.Dst = strings.ToLower(r.Dst)
	// r.Method = strings.ToUpper(r.Method)  // probably not necessary
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
	flag.StringVar(&opts.TimeFormat, "T", "2006-01-02-15:04:05", "timestamp format")
	flag.IntVar(&opts.MinConnCount, "m", 36, "minimum number of connections threshold")
	flag.IntVar(&opts.MaxSources, "s", 5, "maximum number of sources for destination threshold")
	flag.Float64Var(&opts.MinScore, "S", .500, "minimum score threshold")
	flag.Float64Var(&opts.MinDuration, "H", 4, "minimum session duration")
	flag.IntVar(&opts.ColumnTime, "cT", 0, "csv column for timestamp (default 0)")
	flag.IntVar(&opts.ColumnSource, "cS", 2, "csv column for source")
	flag.IntVar(&opts.ColumnDest, "cD", 7, "csv column for destination")
	flag.IntVar(&opts.ColumnByteRecv, "cR", 11, "csv column for bytes recevied")
	flag.IntVar(&opts.ColumnByteSent, "cX", 12, "csv column for bytes sent")
	flag.IntVar(&opts.ColumnMethod, "cM", -1, "csv column for HTTP method")
	flag.IntVar(&opts.ColumnPort, "cP", -1, "csv column for port")
	flag.Float64Var(&opts.WeightTime, "wT", 1.0, "weight value for overall time score")
	flag.Float64Var(&opts.WeightData, "wD", 1.0, "weight value for overall data score")
	flag.Float64Var(&opts.WeightTSSkew, "wTS", 1.0, "weight value for time skew score")
	flag.Float64Var(&opts.WeightTSMadm, "wTM", 1.0, "weight value for time MADM score")
	flag.Float64Var(&opts.WeightTSConn, "wTC", 1.0, "weight value time connection count score")
	flag.Float64Var(&opts.WeightDSSkew, "wDS", 1.0, "weight value for data size skew score")
	flag.Float64Var(&opts.WeightDSMadm, "wDM", 1.0, "weight value for data MADM score")
	flag.Float64Var(&opts.WeightDSSmall, "wDZ", 1.0, "weight value for data smallness score")
	flag.BoolVar(&opts.InputProxy, "P", false, "use Proxy Log CSV Inputs")
	flag.BoolVar(&opts.InputDNS, "D", false, "use DNS Log CSV Inputs (no size analysis)")
	flag.BoolVar(&opts.NoBytes, "B", false, "do not use bytes sent/received in analysis")
	flag.BoolVar(&opts.Caseness, "nocase", false, "disable conversion to lowercase for src and dst")
	flag.Float64Var(&opts.TuneSmallness, "tS", 8192, "tuning value for data smallness score")
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
		if !isFlagPassed("cT") {
			opts.ColumnTime = 0
		}
		if !isFlagPassed("cS") {
			opts.ColumnSource = 2
		}
		if !isFlagPassed("cD") {
			opts.ColumnDest = 7
		}
		if !isFlagPassed("cR") {
			opts.ColumnByteRecv = 11
		}
		if !isFlagPassed("cX") {
			opts.ColumnByteSent = 12
		}
		if !isFlagPassed("d") {
			opts.Comma = " "
		}
		if !isFlagPassed("cM") {
			opts.ColumnMethod = 5
		}
		if !isFlagPassed("cP") {
			opts.ColumnPort = 6
		}
		if !isFlagPassed("t") {
			opts.TimeFormat = "2006-01-02-15:04:05"
		}
	} else if !opts.InputProxy && opts.InputDNS {
		log.Println("INFO: DNS mode selected")
		if !isFlagPassed("cT") {
			opts.ColumnTime = 0
		}
		if !isFlagPassed("cS") {
			opts.ColumnSource = 1
		}
		if !isFlagPassed("cD") {
			opts.ColumnDest = 2
		}
		if !isFlagPassed("cX") {
			opts.ColumnByteSent = -1
		}
		if !isFlagPassed("cR") {
			opts.ColumnByteRecv = -1
		}
		if !isFlagPassed("wD") {
			opts.WeightData = 0
		}
		if !isFlagPassed("B") {
			opts.NoBytes = true
		}
		if !isFlagPassed("t") {
			opts.TimeFormat = "02-Jan-2006-15:04:05"
		}
	}

	return opts
}

// print scored records output, and write to file if needed
// TODO revisit output format
func writeOutput(scoredRecords []ScoredRecord, outputFile string, noBytes, isPort, isMethod bool) {
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
		var strPort string
		var strMethod string
		if isPort {
			strPort = strconv.Itoa(scoredRecord.Port)
		}
		if isMethod {
			strMethod = scoredRecord.Method
		}
		strPortMethod := strings.TrimSpace(fmt.Sprintf("%s %s", strPort, strMethod))
		if noBytes {
			output = fmt.Sprintf("%s -> %s %s %.1f | SCORE: %.3f | (ts: %.3f ds: -) | (tsSkew: %.3f tsMadm: %.3f tsConn: %.3f) (dsSkew: - dsMadm: - dsSmallness: -)\n",
				scoredRecord.Src, scoredRecord.Dst, strPortMethod, scoredRecord.Duration, scoredRecord.Score, scoredRecord.TSScore, scoredRecord.TSSkew, scoredRecord.TSMadm, scoredRecord.TSConn)
		} else {
			output = fmt.Sprintf("%s -> %s %s %.1f | SCORE: %.3f | (ts: %.3f ds: %.3f) | (tsSkew: %.3f tsMadm: %.3f tsConn: %.3f) (dsSkew: %.3f dsMadm: %.3f dsSmallness: %.3f)\n",
				scoredRecord.Src, scoredRecord.Dst, strPortMethod, scoredRecord.Duration, scoredRecord.Score, scoredRecord.TSScore, scoredRecord.DSScore, scoredRecord.TSSkew, scoredRecord.TSMadm,
				scoredRecord.TSConn, scoredRecord.DSSkew, scoredRecord.DSMadm, scoredRecord.DSSmall)
		}
		// print to file if output filename exists, otherwise print to console
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

// func () continueOrDont {
//     reader := bufio.NewReader(os.Stdin)
//     fmt.Print("Do you want to continue? (Y/N): ")
//     text, _ := reader.ReadString('\n')
//     text = strings.TrimSpace(text)
//     if strings.ToLower(text) == "y" {
//         fmt.Println("Continuing...")
//         // continue with the program
//     } else if strings.ToLower(text) == "n" {
//         fmt.Println("Exiting...")
//         os.Exit(0)
//     }
// }

// groups records by source and destination, removing rows with duplicate timestamps,
// keeping the highest byte value.
// TODO revisit this methodology
func groupRecords(records []Record, groupByPort, groupByMethod bool) []GroupedRecord {
	groupsMap := make(map[string]GroupedRecord)

	for _, record := range records {
		key := record.Src + " " + record.Dst
		if groupByPort {
			key += " " + strconv.Itoa(record.Port)
		}
		if groupByMethod {
			key += " " + record.Method
		}

		groupedRecord, ok := groupsMap[key]

		if !ok {
			groupedRecord = GroupedRecord{
				Src:           record.Src,
				Dst:           record.Dst,
				Port:          record.Port,
				Method:        record.Method,
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
func madmFloat(deltas []float64) float64 {
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
	return madmFloat(floatSizes)
}
