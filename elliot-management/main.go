package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

var hosts = []string{"elliottmgmt.com"}

func GetAnalyze(host string) ([]byte, error) {
	resp, err := http.Get("https://api.ssllabs.com/api/v2/analyze?host=" + host)
	if nil != err {
		println("Request Error:")
		println(err.Error())
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

func GetEndpointData(ip string) ([]byte, error) {
	resp, err := http.Get("https://api.ssllabs.com/api/v2/getEndpointData?host=elliottmgmt.com&s=" + ip)
	if nil != err {
		println("Request Error:")
		println(err.Error())
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

func main() {
	for _, host := range hosts {
		resp, err := GetAnalyze(host)
		if err != nil {
			fmt.Println(err)
			return
		}
		//LOG: Retrieved IP address payload
		payload_to_response := make(map[string]interface{})
		json.Unmarshal(resp, &payload_to_response)
		//LOG: Parsed IP address payload

		type AnalyzePayload struct {
			Host      string                   `json:"host"`
			Status    string                   `json:"status"`
			StartTime float64                  `json:"startTime"`
			Endpoint  []map[string]interface{} `json:"endpoints"`
		}

		var st AnalyzePayload
		json.Unmarshal(resp, &st)
		if len(st.Endpoint) < 1 {
			return
		}

		ipAddress, ok := st.Endpoint[0]["ipAddress"].(string)
		if !ok {
			return
		}
		//LOG: IP address: + ipAddress

		resp, err = GetEndpointData(ipAddress)
		if err != nil {
			return
		}
		json.Unmarshal(resp, &payload_to_response)

		//LOG: PARSING EndpointData PAYLOAD
		startTimeUnix := payload_to_response["details"].(map[string]interface{})["cert"].(map[string]interface{})["notBefore"].(float64)
		endTimeUnix := payload_to_response["details"].(map[string]interface{})["cert"].(map[string]interface{})["notAfter"].(float64)
		// rsaSize := payload_to_response["details"].(map[string]interface{})["key"].(map[string]interface{})["size"].(float64)
		// alg := payload_to_response["details"].(map[string]interface{})["key"].(map[string]interface{})["alg"].(string)

		names := payload_to_response["details"].(map[string]interface{})["cert"].(map[string]interface{})["commonNames"].([]interface{})
		names_str := make([]string, 0, len(names))
		for _, name := range names {
			names_str = append(names_str, name.(string))
		}

		alternative_names := payload_to_response["details"].(map[string]interface{})["cert"].(map[string]interface{})["altNames"].([]interface{})
		alternative_names_str := make([]string, 0, len(alternative_names))
		for _, name := range alternative_names {
			alternative_names_str = append(alternative_names_str, name.(string))
		}

		sigAlg := payload_to_response["details"].(map[string]interface{})["cert"].(map[string]interface{})["sigAlg"].(string)
		issuer := payload_to_response["details"].(map[string]interface{})["cert"].(map[string]interface{})["issuerLabel"].(string)
		crlRevocationStatus := payload_to_response["details"].(map[string]interface{})["cert"].(map[string]interface{})["crlRevocationStatus"].(float64)
		ocspRevocationStatus := payload_to_response["details"].(map[string]interface{})["cert"].(map[string]interface{})["ocspRevocationStatus"].(float64)
		//LOG: EndpointData Payload Parsed

		var certificateValidity string
		var ocspRevocationStatusInt int = int(ocspRevocationStatus)
		var crlRevocationStatusInt int = int(crlRevocationStatus)

		// LOG: CRLRevocationStatus: crlRevocationStatus  OCSPRevocationStatus: ocspRevocationStatus
		if (crlRevocationStatus == 2 && ocspRevocationStatus == 4) || (crlRevocationStatus == 4 && ocspRevocationStatus == 2) {
			certificateValidity = "Certificate Valid\n"
		} else {
			certificateValidity = "Certificate Invalid\n" +
				"OCSP Revocation Status: " + fmt.Sprint(ocspRevocationStatusInt) + "\n" +
				"CRL Revocation Status" + fmt.Sprint(crlRevocationStatusInt) + "\n"
		}
		var startTimeUnixInt int64 = int64(startTimeUnix)
		var endTimeUnixInt int64 = int64(endTimeUnix)
		startTimeUnixTime := time.Unix(startTimeUnixInt, 0)
		endTimeUnixTime := time.Unix(endTimeUnixInt, 0)
		//LOG: All Info Assembled

		report := "Attempting to verify certificate for elliotmgmt.com\n" +
			certificateValidity +
			"Issuer: " + issuer + "\n" +
			"Valid from: " + startTimeUnixTime.Format(time.RFC850) + "\n" +
			"Valid until: " + endTimeUnixTime.Format(time.RFC850) + "\n" +
			"Common Names: " + strings.Join(names_str, ",") + "\n" +
			"Alternate Names: " + strings.Join(alternative_names_str, ",") + "\n" +
			"Signature Algorithim: " + sigAlg + "\n"

		//LOG: Report Assembled
		print(report)
	}
	return
}
