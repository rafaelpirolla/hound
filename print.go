// /////////////////////////////////////////////////////////////////////////////

package main

// /////////////////////////////////////////////////////////////////////////////

import (
	"container/list"
	"errors"
	"fmt"
)

// /////////////////////////////////////////////////////////////////////////////
// GLOBALS
// /////////////////////////////////////////////////////////////////////////////

var ()

// /////////////////////////////////////////////////////////////////////////////
// TYPES
// /////////////////////////////////////////////////////////////////////////////

type Printer interface {
	print(*list.List)
}

type ScreenPrinter struct {
}

// /////////////////////////////////////////////////////////////////////////////
// METHODS
// /////////////////////////////////////////////////////////////////////////////

func NewScreenPrinter() *ScreenPrinter {
	spr := new(ScreenPrinter)
	return spr
}

// /////////////////////////////////////////////////////////////////////////////

func (scpr *ScreenPrinter) print(cns *list.List) {
	for e := (*cns).Front(); e != nil; e = e.Next() {
		cn := e.Value.(*TCPConnection)

		minRttSrcToDst, err := minRtt(&cn.SamplesSrcToDst)

		if err != nil {
			minRttSrcToDst = -1.0
		}

		maxRttSrcToDst, err := maxRtt(&cn.SamplesSrcToDst)

		if err != nil {
			maxRttSrcToDst = -1.0
		}

		avgRttSrcToDst, err := avgRtt(&cn.SamplesSrcToDst)

		if err != nil {
			avgRttSrcToDst = -1.0
		}

		minRttDstToSrc, err := minRtt(&cn.SamplesDstToSrc)

		if err != nil {
			minRttSrcToDst = -1.0
		}

		maxRttDstToSrc, err := maxRtt(&cn.SamplesDstToSrc)

		if err != nil {
			maxRttSrcToDst = -1.0
		}

		avgRttDstToSrc, err := avgRtt(&cn.SamplesDstToSrc)

		if err != nil {
			avgRttSrcToDst = -1.0
		}

		fmt.Printf("%s:%d -> %s:%d\n", cn.SrcIP.String(), cn.SrcPort, cn.DstIP.String(), cn.DstPort)
		fmt.Printf("\tiRTT: %.4f\n", cn.IRtt)
		fmt.Printf("\tSrc to Dst -> [min: %.6f, max: %.6f, avg: %.6f]\n", minRttSrcToDst, maxRttSrcToDst, avgRttSrcToDst)
		fmt.Printf("\tDst to Src -> [min: %.6f, max: %.6f, avg: %.6f]\n", minRttDstToSrc, maxRttDstToSrc, avgRttDstToSrc)
		fmt.Printf("\tSamples Src to Dst: %v\n", extractRttList(&cn.SamplesSrcToDst))
		fmt.Printf("\tSamples Dst to Src: %v\n", extractRttList(&cn.SamplesDstToSrc))
	}

}

// /////////////////////////////////////////////////////////////////////////////

func isCustomerIP(ipAddress string, config *Config) bool {
	for _, ip := range config.CustomerIPs {
		if ipAddress == ip {
			return true
		}
	}

	return false
}

// /////////////////////////////////////////////////////////////////////////////

func extractRttList(sm *SampleMap) []float64 {
	var rttList []float64

	for _, sp := range *sm {
		rttList = append(rttList, sp.Rtt)
	}

	return rttList
}

// /////////////////////////////////////////////////////////////////////////////

func minRtt(sm *SampleMap) (float64, error) {
	rttList := extractRttList(sm)

	if len(rttList) > 0 {
		minRtt := rttList[0]

		for _, rtt := range rttList {
			if rtt > 0 && rtt < minRtt {
				minRtt = rtt
			}
		}

		return minRtt, nil
	}

	return 0.0, errors.New("unknown minimum rtt")
}

// /////////////////////////////////////////////////////////////////////////////

func maxRtt(sm *SampleMap) (float64, error) {
	rttList := extractRttList(sm)

	if len(rttList) > 0 {
		maxRtt := rttList[0]

		for _, rtt := range rttList {
			if rtt > maxRtt {
				maxRtt = rtt
			}
		}

		return maxRtt, nil
	}

	return 0.0, errors.New("unknown maximum rtt")
}

// /////////////////////////////////////////////////////////////////////////////

func avgRtt(sm *SampleMap) (float64, error) {
	rttList := extractRttList(sm)

	if len(rttList) > 0 {
		var totalRtt float64

		count := 0

		for _, rtt := range rttList {
			if rtt > 0.0 {
				totalRtt = totalRtt + rtt
				count = count + 1
			}
		}

		if count == 0 {
			count = 1
		}

		totalAvg := totalRtt / float64(count)

		return totalAvg, nil
	}

	return 0.0, errors.New("unknown average rtt")
}

// /////////////////////////////////////////////////////////////////////////////
