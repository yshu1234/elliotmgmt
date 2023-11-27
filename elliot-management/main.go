package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

var hosts = []string{"elliottmgmt.com"}

const retry_attempts = 5
const endpointDataAddress = "https://api.ssllabs.com/api/v2/getEndpointData?host=elliottmgmt.com&s="
const analyzeDataAddress = "https://api.ssllabs.com/api/v2/analyze?host="

type EndpointDataInfo struct {
	Details struct {
		Cert struct {
			NotBefore            float64  `json:"notBefore"`
			NotAfter             float64  `json:"notAfter"`
			CommonNames          []string `json:"commonNames"`
			AlterNativeNames     []string `json:"altNames"`
			SigAlg               string   `json:"sigAlg"`
			IssuerLabel          string   `json:"issuerLabel"`
			CrlRevocationStatus  float64  `json:"crlRevocationStatus"`
			OcspRevocationStatus float64  `json:"ocspRevocationStatus"`
		} `json:"cert"`
	} `json:"details"`
}

func retryHttpGetCall(endpoint string) (*http.Response, error) {
	var err error
	for retry_attempt := 0; retry_attempt < retry_attempts; retry_attempt += 1 {
		resp, err := http.Get(endpoint)
		if nil == err {
			return resp, nil
		}
	}

	return nil, err
}

func GetAndReadPayload(address string) ([]byte, error) {
	resp, err := retryHttpGetCall(address)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if nil != err {
		println("Read Error:")
		println(err.Error())
		return nil, err
	}

	return body, nil
}

func GetIPAddress(host string) (string, error) {
	// LOG: Retrieving Analyze address payload
	resp, err := GetAndReadPayload(host)
	if err != nil {
		return "", err
	}
	payload_to_response := make(map[string]interface{})
	json.Unmarshal(resp, &payload_to_response)
	//LOG: Parsed Analyze address payload

	type AnalyzePayload struct {
		Host      string                   `json:"host"`
		Status    string                   `json:"status"`
		StartTime float64                  `json:"startTime"`
		Endpoint  []map[string]interface{} `json:"endpoints"`
	}

	var st AnalyzePayload
	json.Unmarshal(resp, &st)
	if len(st.Endpoint) < 1 {
		return "", errors.New("No endpoints found in analyze payload. Rerunning once usually fixes this.")
	}

	ipAddress, ok := st.Endpoint[0]["ipAddress"].(string)
	if !ok {
		return "", errors.New("No ip address listed in payload.  Rerunning once usually fixes this.")
	}
	return ipAddress, nil
}

func ConstructReport(endpointDataInfo EndpointDataInfo) string {
	var certificateValidity string
	var ocspRevocationStatusInt int = int(endpointDataInfo.Details.Cert.OcspRevocationStatus)
	var crlRevocationStatusInt int = int(endpointDataInfo.Details.Cert.CrlRevocationStatus)

	// LOG: CRLRevocationStatus: crlRevocationStatus  OCSPRevocationStatus: ocspRevocationStatus
	if (crlRevocationStatusInt == 2 && ocspRevocationStatusInt == 4) || (crlRevocationStatusInt == 4 && ocspRevocationStatusInt == 2) {
		certificateValidity = "Certificate Valid\n"
	} else {
		certificateValidity = "Certificate Invalid\n" +
			"OCSP Revocation Status: " + fmt.Sprint(ocspRevocationStatusInt) + "\n" +
			"CRL Revocation Status" + fmt.Sprint(crlRevocationStatusInt) + "\n"
	}
	var startTimeUnixInt int64 = int64(endpointDataInfo.Details.Cert.NotBefore)
	var endTimeUnixInt int64 = int64(endpointDataInfo.Details.Cert.NotAfter)
	startTimeUnixTime := time.Unix(startTimeUnixInt, 0)
	endTimeUnixTime := time.Unix(endTimeUnixInt, 0)
	//LOG: All Info Assembled

	report := "Attempting to verify certificate for elliotmgmt.com\n" +
		certificateValidity +
		"Issuer: " + endpointDataInfo.Details.Cert.IssuerLabel + "\n" +
		"Valid from: " + startTimeUnixTime.Format(time.RFC850) + "\n" +
		"Valid until: " + endTimeUnixTime.Format(time.RFC850) + "\n" +
		"Common Names: " + strings.Join(endpointDataInfo.Details.Cert.CommonNames, ",") + "\n" +
		"Alternate Names: " + strings.Join(endpointDataInfo.Details.Cert.AlterNativeNames, ",") + "\n" +
		"Signature Algorithim: " + endpointDataInfo.Details.Cert.SigAlg + "\n"

	return report
}

func main() {
	for _, host := range hosts {
		//LOG: Retrieving host info for: "host"
		ipAddress, err := GetIPAddress(analyzeDataAddress + host)
		if err != nil {
			fmt.Println(err)
			continue
		}
		//LOG: IP address: "ipAddress"
		resp, err := GetAndReadPayload(endpointDataAddress + ipAddress)
		if err != nil {
			return
		}

		var endpointDataInfo EndpointDataInfo
		// //LOG: PARSING EndpointData PAYLOAD
		json.Unmarshal(resp, &endpointDataInfo)

		report := ConstructReport(endpointDataInfo)
		//LOG: Report Assembled
		print(report)
	}
	return
}
