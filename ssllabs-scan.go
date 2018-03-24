// +build go1.3

/*
 * Licensed to Qualys, Inc. (QUALYS) under one or more
 * contributor license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * QUALYS licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import "bufio"
import "crypto/tls"
import "encoding/json"
import "errors"
import "flag"
import "fmt"
import "github.com/olivere/elastic"
import "golang.org/x/net/context"
import "io"
import "io/ioutil"
import "log"
import "math/rand"
import "net"
import "net/http"
import "net/url"
import "os"
import "regexp"
import "sort"
import "strconv"
import "strings"
import "sync/atomic"
import "time"

const (
	LOG_NONE     = -1
	LOG_EMERG    = 0
	LOG_ALERT    = 1
	LOG_CRITICAL = 2
	LOG_ERROR    = 3
	LOG_WARNING  = 4
	LOG_NOTICE   = 5
	LOG_INFO     = 6
	LOG_DEBUG    = 7
	LOG_TRACE    = 8
)

var USER_AGENT = "ssllabs-scan v1.4.0 (stable $Id$)"

var logLevel = LOG_NOTICE

// How many assessment do we have in progress?
var activeAssessments = 0

// How many assessments does the server think we have in progress?
var currentAssessments = -1

// The maximum number of assessments we can have in progress at any one time.
var maxAssessments = -1

var requestCounter uint64 = 0

var apiLocation = "https://api.ssllabs.com/api/v2"

var globalNewAssessmentCoolOff int64 = 1100

var globalIgnoreMismatch = false

var globalStartNew = true

var globalFromCache = false

var globalMaxAge = 0

var globalInsecure = false

var httpClient *http.Client

var conf_json_flat *bool

var useElasticOutput *bool

var elasticClient *elastic.Client

var elasticIndex string = "ssllabs-scan"

var exclude_pattern *regexp.Regexp = nil

var include_pattern *regexp.Regexp = nil

type LabsError struct {
	Field   string
	Message string
}

type LabsErrorResponse struct {
	ResponseErrors []LabsError `json:"errors"`
}

func (e LabsErrorResponse) Error() string {
	msg, err := json.Marshal(e)
	if err != nil {
		return err.Error()
	} else {
		return string(msg)
	}
}

type LabsKey struct {
	Size       int
	Strength   int
	Alg        string
	DebianFlaw bool
	Q          int
}

type LabsCert struct {
	Subject              string
	CommonNames          []string
	AltNames             []string
	NotBefore            int64
	NotAfter             int64
	IssuerSubject        string
	SigAlg               string
	IssuerLabel          string
	RevocationInfo       int
	CrlURIs              []string
	OcspURIs             []string
	RevocationStatus     int
	CrlRevocationStatus  int
	OcspRevocationStatus int
	Sgc                  int
	ValidationType       string
	Issues               int
	Sct                  bool
	MustStaple           int
}

type LabsChainCert struct {
	Subject              string
	Label                string
	NotBefore            int64
	NotAfter             int64
	IssuerSubject        string
	IssuerLabel          string
	SigAlg               string
	Issues               int
	KeyAlg               string
	KeySize              int
	KeyStrength          int
	RevocationStatus     int
	CrlRevocationStatus  int
	OcspRevocationStatus int
	Raw                  string
}

type LabsChain struct {
	Certs  []LabsChainCert
	Issues int
}

type LabsProtocol struct {
	Id               int
	Name             string
	Version          string
	V2SuitesDisabled bool
	ErrorMessage     bool
	Q                int
}

type LabsSimClient struct {
	Id          int
	Name        string
	Platform    string
	Version     string
	IsReference bool
}

type LabsSimulation struct {
	Client     LabsSimClient
	ErrorCode  int
	Attempts   int
	ProtocolId int
	SuiteId    int
	KxInfo     string
}

type LabsSimDetails struct {
	Results []LabsSimulation
}

type LabsSuite struct {
	Id             int
	Name           string
	CipherStrength int
	DhStrength     int
	DhP            int
	DhG            int
	DhYs           int
	EcdhBits       int
	EcdhStrength   int
	Q              int
}

type LabsSuites struct {
	List       []LabsSuite
	Preference bool
}

type LabsHstsPolicy struct {
	LONG_MAX_AGE      int64
	Header            string
	Status            string
	Error             string
	MaxAge            int64
	IncludeSubDomains bool
	Preload           bool
	Directives        map[string]string
}

type LabsHstsPreload struct {
	Source     string
	Status     string
	Error      string
	SourceTime int64
}

type LabsHpkpPin struct {
	HashFunction string
	Value        string
}

type LabsHpkpDirective struct {
	Name         string
	Value        string
}

type LabsHpkpPolicy struct {
	Header            string
	Status            string
	Error             string
	MaxAge            int64
	IncludeSubDomains bool
	ReportUri         string
	Pins              []LabsHpkpPin
	MatchedPins       []LabsHpkpPin
	Directives        []LabsHpkpDirective
}

type DrownHost struct {
	Ip      string
	Export  bool
	Port    int
	Special bool
	Sslv2   bool
	Status  string
}

type LabsEndpointDetails struct {
	HostStartTime                  int64
	Key                            LabsKey
	Cert                           LabsCert
	Chain                          LabsChain
	Protocols                      []LabsProtocol
	Suites                         LabsSuites
	ServerSignature                string
	PrefixDelegation               bool
	NonPrefixDelegation            bool
	VulnBeast                      bool
	RenegSupport                   int
	SessionResumption              int
	CompressionMethods             int
	SupportsNpn                    bool
	NpnProtocols                   string
	SessionTickets                 int
	OcspStapling                   bool
	StaplingRevocationStatus       int
	StaplingRevocationErrorMessage string
	SniRequired                    bool
	HttpStatusCode                 int
	HttpForwarding                 string
	ForwardSecrecy                 int
	SupportsRc4                    bool
	Rc4WithModern                  bool
	Rc4Only                        bool
	Sims                           LabsSimDetails
	Heartbleed                     bool
	Heartbeat                      bool
	OpenSslCcs                     int
	OpenSSLLuckyMinus20            int
	Poodle                         bool
	PoodleTls                      int
	FallbackScsv                   bool
	Freak                          bool
	HasSct                         int
	DhPrimes                       []string
	DhUsesKnownPrimes              int
	DhYsReuse                      bool
	Logjam                         bool
	ChaCha20Preference             bool
	HstsPolicy                     LabsHstsPolicy
	HstsPreloads                   []LabsHstsPreload
	HpkpPolicy                     LabsHpkpPolicy
	HpkpRoPolicy                   LabsHpkpPolicy
	DrownHosts                     []DrownHost
	DrownErrors                    bool
	DrownVulnerable                bool
}

type LabsEndpoint struct {
	IpAddress            string
	ServerName           string
	StatusMessage        string
	StatusDetailsMessage string
	Grade                string
	GradeTrustIgnored    string
	HasWarnings          bool
	IsExceptional        bool
	Progress             int
	Duration             int
	Eta                  int
	Delegation           int
	Details              LabsEndpointDetails
}

type LabsReport struct {
	Host            string
	Port            int
	Protocol        string
	IsPublic        bool
	Status          string
	StatusMessage   string
	StartTime       int64
	TestTime        int64
	EngineVersion   string
	CriteriaVersion string
	CacheExpiryTime int64
	Endpoints       []LabsEndpoint
	CertHostnames   []string
	rawJSON         string
}

type LabsResults struct {
	reports   []LabsReport
	responses []string
}

type LabsInfo struct {
	EngineVersion        string
	CriteriaVersion      string
	MaxAssessments       int
	CurrentAssessments   int
	NewAssessmentCoolOff int64
	Messages             []string
}

func invokeGetRepeatedly(url string) (*http.Response, []byte, error) {
	retryCount := 0

	for {
		var reqId = atomic.AddUint64(&requestCounter, 1)

		if logLevel >= LOG_DEBUG {
			log.Printf("[DEBUG] Request #%v: %v", reqId, url)
		}

		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return nil, nil, err
		}

		req.Header.Add("User-Agent", USER_AGENT)

		resp, err := httpClient.Do(req)
		if err == nil {
			if logLevel >= LOG_DEBUG {
				log.Printf("[DEBUG] Response #%v status: %v %v", reqId, resp.Proto, resp.Status)
			}

			if logLevel >= LOG_TRACE {
				for key, values := range resp.Header {
					for _, value := range values {
						log.Printf("[TRACE] %v: %v\n", key, value)
					}
				}
			}

			if logLevel >= LOG_NOTICE {
				for key, values := range resp.Header {
					if strings.ToLower(key) == "x-message" {
						for _, value := range values {
							log.Printf("[NOTICE] Server message: %v\n", value)
						}
					}
				}
			}

			// Update current assessments.
			headerValue := resp.Header.Get("X-Current-Assessments")
			if headerValue != "" {
				i, err := strconv.Atoi(headerValue)
				if err == nil {
					if currentAssessments != i {
						currentAssessments = i

						if logLevel >= LOG_DEBUG {
							log.Printf("[DEBUG] Server set current assessments to %v", headerValue)
						}
					}
				} else {
					if logLevel >= LOG_WARNING {
						log.Printf("[WARNING] Ignoring invalid X-Current-Assessments value (%v): %v", headerValue, err)
					}
				}
			}

			// Update maximum assessments.
			headerValue = resp.Header.Get("X-Max-Assessments")
			if headerValue != "" {
				i, err := strconv.Atoi(headerValue)
				if err == nil {
					if maxAssessments != i {
						maxAssessments = i

						if maxAssessments <= 0 {
							log.Fatalf("[ERROR] Server doesn't allow further API requests")
						}

						if logLevel >= LOG_DEBUG {
							log.Printf("[DEBUG] Server set maximum assessments to %v", headerValue)
						}
					}
				} else {
					if logLevel >= LOG_WARNING {
						log.Printf("[WARNING] Ignoring invalid X-Max-Assessments value (%v): %v", headerValue, err)
					}
				}
			}

			// Retrieve the response body.
			defer resp.Body.Close()

			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				return nil, nil, err
			}

			if logLevel >= LOG_TRACE {
				log.Printf("[TRACE] Response #%v body:\n%v", reqId, string(body))
			}

			return resp, body, nil
		} else {
			if strings.Contains(err.Error(), "EOF") {
				// Server closed a persistent connection on us, which
				// Go doesn't seem to be handling well. So we'll try one
				// more time.
				if retryCount > 5 {
					log.Fatalf("[ERROR] Too many HTTP requests (5) failed with EOF (ref#2)")
				}

				if logLevel >= LOG_DEBUG {
					log.Printf("[DEBUG] HTTP request failed with EOF (ref#2)")
				}
			} else {
				if retryCount > 5 {
					log.Fatalf("[ERROR] HTTP request failed after 5 retries: %v (ref#2)", err.Error())
				} else {
					invokeSleepTime(resp.StatusCode)
				}
			}

			retryCount++
		}
	}
}

func invokeSleepTime(statusCode int) {
	sleepTime := 15 + rand.Int31n(15)
	if logLevel >= LOG_NOTICE {
		log.Printf("[NOTICE] Sleeping for %v minutes after a %v response", sleepTime, statusCode)
	}
	time.Sleep(time.Duration(sleepTime) * time.Minute)
}

func invokeApi(command string) (*http.Response, []byte, error) {
	var url = apiLocation + "/" + command

	for {
		resp, body, err := invokeGetRepeatedly(url)
		if err != nil {
			return nil, nil, err
		}

		// Status codes 429, 503, and 529 essentially mean try later. Thus,
		// if we encounter them, we sleep for a while and try again.
		if resp.StatusCode == 429 {
			return resp, body, errors.New("Assessment failed: 429")
		} else if (resp.StatusCode == 503) || (resp.StatusCode == 529) {
			// In case of the overloaded server, randomize the sleep time so
			// that some clients reconnect earlier and some later.
			invokeSleepTime(resp.StatusCode)
		} else if (resp.StatusCode != 200) && (resp.StatusCode != 400) {
			log.Fatalf("[ERROR] Unexpected response status code %v", resp.StatusCode)
		} else {
			return resp, body, nil
		}
	}
}

func invokeInfo() (*LabsInfo, error) {
	var command = "info"

	_, body, err := invokeApi(command)
	if err != nil {
		return nil, err
	}

	var labsInfo LabsInfo
	err = json.Unmarshal(body, &labsInfo)
	if err != nil {
		log.Printf("[ERROR] JSON unmarshal error: %v", err)
		return nil, err
	}

	return &labsInfo, nil
}

func invokeAnalyze(host string, startNew bool, fromCache bool) (*LabsReport, error) {
	var command = "analyze?host=" + host + "&all=done"

	if fromCache {
		command = command + "&fromCache=on"

		if globalMaxAge != 0 {
			command = command + "&maxAge=" + strconv.Itoa(globalMaxAge)
		}
	} else if startNew {
		command = command + "&startNew=on"
	}

	if globalIgnoreMismatch {
		command = command + "&ignoreMismatch=on"
	}

	resp, body, err := invokeApi(command)
	if err != nil {
		return nil, err
	}

	// Use the status code to determine if the response is an error.
	if resp.StatusCode == 400 {
		// Parameter validation error.

		var apiError LabsErrorResponse
		err = json.Unmarshal(body, &apiError)
		if err != nil {
			log.Printf("[ERROR] JSON unmarshal error: %v", err)
			return nil, err
		}

		return nil, apiError
	} else {
		// We should have a proper response.

		var analyzeResponse LabsReport
		err = json.Unmarshal(body, &analyzeResponse)
		if err != nil {
			log.Printf("[ERROR] JSON unmarshal error: %v", err)
			return nil, err
		}

		// Add the JSON body to the response
		analyzeResponse.rawJSON = string(body)

		return &analyzeResponse, nil
	}
}

type Event struct {
	host      string
	eventType int
	report    *LabsReport
}

const (
	ASSESSMENT_FAILED   = -1
	ASSESSMENT_STARTING = 0
	ASSESSMENT_COMPLETE = 1
)

func NewAssessment(host string, eventChannel chan Event) {
	eventChannel <- Event{host, ASSESSMENT_STARTING, nil}

	var report *LabsReport
	var startTime int64 = -1
	var startNew = globalStartNew

	for {
		myResponse, err := invokeAnalyze(host, startNew, globalFromCache)
		if err != nil {
			eventChannel <- Event{host, ASSESSMENT_FAILED, nil}
			return
		}

		if startTime == -1 {
			startTime = myResponse.StartTime
			startNew = false
		} else {
			// Abort this assessment if the time we receive in a follow-up check
			// is older than the time we got when we started the request. The
			// upstream code should then retry the hostname in order to get
			// consistent results.
			if myResponse.StartTime > startTime {
				eventChannel <- Event{host, ASSESSMENT_FAILED, nil}
				return
			} else {
				startTime = myResponse.StartTime
			}
		}

		if (myResponse.Status == "READY") || (myResponse.Status == "ERROR") {
			report = myResponse
			break
		}

		time.Sleep(5 * time.Second)
	}

	eventChannel <- Event{host, ASSESSMENT_COMPLETE, report}
}

type HostProvider struct {
	hostnames   []string
	StartingLen int
}

func NewHostProvider(hs []string) *HostProvider {
	hostnames := make([]string, len(hs))
	copy(hostnames, hs)
	hostProvider := HostProvider{hostnames, len(hs)}
	return &hostProvider
}

func (hp *HostProvider) next() (string, bool) {
	if len(hp.hostnames) == 0 {
		return "", false
	}

	var e string
	e, hp.hostnames = hp.hostnames[0], hp.hostnames[1:]

	return e, true
}

func (hp *HostProvider) retry(host string) {
	hp.hostnames = append(hp.hostnames, host)
}

type Manager struct {
	hostProvider         *HostProvider
	FrontendEventChannel chan Event
	BackendEventChannel  chan Event
	results              *LabsResults
}

func NewManager(hostProvider *HostProvider) *Manager {
	manager := Manager{
		hostProvider:         hostProvider,
		FrontendEventChannel: make(chan Event),
		BackendEventChannel:  make(chan Event),
		results:              &LabsResults{reports: make([]LabsReport, 0)},
	}

	go manager.run()

	return &manager
}

func (manager *Manager) startAssessment(h string) {
	go NewAssessment(h, manager.BackendEventChannel)
	activeAssessments++
}

func (manager *Manager) run() {
	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: globalInsecure},
		DisableKeepAlives: false,
		Proxy:             http.ProxyFromEnvironment,
	}

	httpClient = &http.Client{Transport: transport}

	// Ping SSL Labs to determine how many concurrent
	// assessments we're allowed to use. Print the API version
	// information and the limits.

	labsInfo, err := invokeInfo()
	if err != nil {
		// TODO Signal error so that we return the correct exit code
		close(manager.FrontendEventChannel)
	}

	if logLevel >= LOG_INFO {
		log.Printf("[INFO] SSL Labs v%v (criteria version %v)", labsInfo.EngineVersion, labsInfo.CriteriaVersion)
	}

	if logLevel >= LOG_NOTICE {
		for _, message := range labsInfo.Messages {
			log.Printf("[NOTICE] Server message: %v", message)
		}
	}

	maxAssessments = labsInfo.MaxAssessments

	if maxAssessments <= 0 {
		if logLevel >= LOG_WARNING {
			log.Printf("[WARNING] You're not allowed to request new assessments")
		}
	}

	moreAssessments := true

	if labsInfo.NewAssessmentCoolOff >= 1000 {
		globalNewAssessmentCoolOff = 100 + labsInfo.NewAssessmentCoolOff
	} else {
		if logLevel >= LOG_WARNING {
			log.Printf("[WARNING] Info.NewAssessmentCoolOff too small: %v", labsInfo.NewAssessmentCoolOff)
		}
	}

	for {
		select {
		// Handle assessment events (e.g., starting and finishing).
		case e := <-manager.BackendEventChannel:
			if e.eventType == ASSESSMENT_FAILED {
				activeAssessments--
				manager.hostProvider.retry(e.host)
			}

			if e.eventType == ASSESSMENT_STARTING {
				if logLevel >= LOG_INFO {
					log.Printf("[INFO] Assessment starting: %v", e.host)
				}
			}

			if e.eventType == ASSESSMENT_COMPLETE {
				if logLevel >= LOG_INFO {
					msg := ""

					if len(e.report.Endpoints) == 0 {
						msg = fmt.Sprintf("[WARN] Assessment failed: %v (%v)", e.host, e.report.StatusMessage)
					} else if len(e.report.Endpoints) > 1 {
						msg = fmt.Sprintf("[INFO] Assessment complete: %v (%v hosts in %v seconds)",
							e.host, len(e.report.Endpoints), (e.report.TestTime-e.report.StartTime)/1000)
					} else {
						msg = fmt.Sprintf("[INFO] Assessment complete: %v (%v host in %v seconds)",
							e.host, len(e.report.Endpoints), (e.report.TestTime-e.report.StartTime)/1000)
					}

					for _, endpoint := range e.report.Endpoints {
						if endpoint.Grade != "" {
							msg = msg + "\n    " + endpoint.IpAddress + ": " + endpoint.Grade
						} else {
							msg = msg + "\n    " + endpoint.IpAddress + ": Err: " + endpoint.StatusMessage
						}
					}

					log.Println(msg)
				}

				activeAssessments--

				data, err := prepareData(e.report.rawJSON)
				if err != nil {
					log.Fatalf("[ERROR] Unable to prepare the json data: %v", err)
					break
				}
				manager.results.reports = append(manager.results.reports, *e.report)
				manager.results.responses = append(manager.results.responses, data)
				manager.FrontendEventChannel <- Event{e.host, ASSESSMENT_COMPLETE, e.report}
				if *useElasticOutput {
					_, err = elasticClient.Index().
											Index(elasticIndex).
											Type(elasticIndex).
											Id(e.host).
											BodyJson(data).
											Do(context.TODO())
					if err != nil {
						log.Fatalf("[ERROR] Unable to push json data to elasticsearch: %v", err)
						break
					}
					if logLevel >= LOG_DEBUG {
						log.Printf("[DEBUG] Pushed %v to elasticsearch index %v", e.host, elasticIndex)
					}
				}
				if logLevel >= LOG_DEBUG {
					log.Printf("[DEBUG] Active assessments: %v (more: %v)", activeAssessments, moreAssessments)
				}
			}

			// Are we done?
			if (activeAssessments == 0) && (moreAssessments == false) {
				close(manager.FrontendEventChannel)
				return
			}

			break

		// Once a second, start a new assessment, provided there are
		// hostnames left and we're not over the concurrent assessment limit.
		default:
			if manager.hostProvider.StartingLen > 0 {
				<-time.NewTimer(time.Duration(globalNewAssessmentCoolOff) * time.Millisecond).C
			}

			if moreAssessments {
				if currentAssessments < maxAssessments {
					host, hasNext := manager.hostProvider.next()
					if hasNext {
						manager.startAssessment(host)
					} else {
						// We've run out of hostnames and now just need
						// to wait for all the assessments to complete.
						moreAssessments = false

						if activeAssessments == 0 {
							close(manager.FrontendEventChannel)
							return
						}
					}
				}
			}
			break
		}
	}
}

func prepareData(rawJson string) (string, error) {
	var nested map[string]interface{}
	err := json.Unmarshal([]byte(rawJson), &nested)
	if err != nil {
		return "", err
	}
	flattened, err := flatten(nested, "")
	if err != nil {
		return "", err
	}

	if !*conf_json_flat {
		flattened = Unflatten(flattened, SplitByDot)
	}

	flatb, err := json.Marshal(&flattened)
	if err != nil {
		return "", err
	}

        return string(flatb), nil
}

func parseLogLevel(level string) int {
	switch {
	case level == "error":
		return LOG_ERROR
	case level == "notice":
		return LOG_NOTICE
	case level == "info":
		return LOG_INFO
	case level == "debug":
		return LOG_DEBUG
	case level == "trace":
		return LOG_TRACE
	}

	log.Fatalf("[ERROR] Unrecognized log level: %v", level)
	return -1
}

func SplitByDot(k string) []string { return strings.Split(k, ".") }

type TokenizerFunc func(string) []string

func Unflatten(m map[string]interface{}, tf TokenizerFunc) map[string]interface{} {
	var tree = make(map[string]interface{})
	for k, v := range m {
		ks := tf(k)
		tr := tree
		for i, tk := range ks[:len(ks)-1] {
			next := ks[i+1]
			if index, err := strconv.Atoi(next); err == nil {
				array, ok := tr[tk]
				if !ok {
					arraynew := make([]map[string]interface{}, 0)
					trnew := make(map[string]interface{})
					arraynew = append(arraynew, trnew)
					tr[tk] = arraynew
					tr = trnew
				} else {
					arrn := array.([]map[string]interface{})
					length := len(arrn)
					var trnew map[string]interface{}
					if (index >= length) {
						trnew = make(map[string]interface{})
						arrn = append(arrn, trnew)
						tr[tk] = arrn
					} else {
						trnew = arrn[index]
					}
					tr = trnew
				}
			} else {
				if _, err := strconv.Atoi(tk); err == nil {
					continue
				}
				trnew, ok := tr[tk]
				if !ok {
					trnew = make(map[string]interface{})
					tr[tk] = trnew
				}
				tr = trnew.(map[string]interface{})
			}
		}
		tr[ks[len(ks)-1]] = v
	}
	return tree
}

func flattenJson(top bool, flatMap map[string]interface{}, nested interface{}, prefix string) error {
	assign := func(newKey string, v interface{}) error {
		switch v.(type) {
		case map[string]interface{}, []interface{}:
			if err := flattenJson(false, flatMap, v, newKey); err != nil {
				return err
			}
		default:
			if exclude_pattern != nil && exclude_pattern.MatchString(newKey) {
				if include_pattern == nil {
					return nil
				}
			} else if exclude_pattern == nil && include_pattern != nil {
				if !include_pattern.MatchString(newKey) {
					return nil
				}
			}
			flatMap[newKey] = v
		}

		return nil
	}

	switch nested.(type) {
	case map[string]interface{}:
		for k, v := range nested.(map[string]interface{}) {
			newKey := enkey(top, prefix, k)
			assign(newKey, v)
		}
	case []interface{}:
		for i, v := range nested.([]interface{}) {
			newKey := enkey(top, prefix, strconv.Itoa(i))
			assign(newKey, v)
		}
	default:
		return nil
	}

	return nil
}

func enkey(top bool, prefix, subkey string) string {
	key := prefix

	if top {
		key += subkey
	} else {
		key += "." + subkey
	}

	return key
}

// flatten generates a flat map from a nested one.  The original may include values of type map, slice and scalar,
// but not struct.  Keys in the flat map will be a compound of descending map keys and slice iterations.
// The presentation of keys is set by style.  A prefix is joined to each key.
func flatten(nested map[string]interface{}, prefix string) (map[string]interface{}, error) {
	flatmap := make(map[string]interface{})

	err := flattenJson(true, flatmap, nested, prefix)
	if err != nil {
		return nil, err
	}

	return flatmap, nil
}

func flattenAndFormatJSON(inputJSON []byte) *[]string {
	var nested map[string]interface{}
	err := json.Unmarshal([]byte(inputJSON), &nested)
	if err != nil {
		panic(err)
	}
	// flatten the JSON structure, recursively
	flattened, err := flatten(nested, "")

	// Make a sorted index, so we can print keys in order
	kIndex := make([]string, len(flattened))
	ki := 0
	for key, _ := range flattened {
		kIndex[ki] = key
		ki++
	}
	sort.Strings(kIndex)

	// Ordered flattened data
	var flatStrings []string
	for _, value := range kIndex {
		flatStrings = append(flatStrings, fmt.Sprintf("\"%v\": %v\n", value, flattened[value]))
	}
	return &flatStrings
}

func downloadFromUrl(url *string) *string {
	urlValue := *url
	tokens := strings.Split(urlValue, "/")
	fileName := tokens[len(tokens)-1]
	if logLevel >= LOG_DEBUG {
		log.Printf("[DEBUG] Downloading %s to %s", urlValue, fileName)
	}

	output, err := os.Create(fileName)
	if err != nil {
		log.Fatalf("[ERROR] Error while creating %s - %s", fileName, err)
	}
	defer output.Close()

	response, err := http.Get(urlValue)
	if err != nil {
		log.Fatalf("[ERROR] Error while downloading %s - %s", urlValue, err)
	}
	defer response.Body.Close()

	n, err := io.Copy(output, response.Body)
	if err != nil {
		log.Fatalf("[ERROR] Error while downloading %s - %s", urlValue, err)
	}

	if logLevel >= LOG_DEBUG {
		log.Printf("[DEBUG] %d bytes downloaded...", n)
	}
	return &fileName
}

func downloadAndReadLines(url *string) ([]string, error) {
	fileName := downloadFromUrl(url)
	return readLines(fileName)
}

func readLines(path *string) ([]string, error) {
	file, err := os.Open(*path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var line = strings.TrimSpace(scanner.Text())
		if (!strings.HasPrefix(line, "#")) && (line != "") {
			lines = append(lines, line)
		}
	}

	return lines, scanner.Err()
}

func validateURL(URL string) bool {
	_, err := url.Parse(URL)
	if err != nil {
		return false
	} else {
		return true
	}
}

func validateHostname(hostname string) bool {
	addrs, err := net.LookupHost(hostname)

	// In some cases there is no error
	// but there are also no addresses
	if err != nil || len(addrs) < 1 {
		return false
	} else {
		return true
	}
}

func ConnectToElastic(hostname *string, index *string, username *string, password *string, mapping string) *elastic.Client {
	var client *elastic.Client
	var err error
	if len(*username) > 0 {
		client, err = elastic.NewClient(elastic.SetURL(*hostname),
						elastic.SetSniff(false),
						elastic.SetErrorLog(log.New(os.Stderr, "ELASTIC ", log.LstdFlags)),
						elastic.SetBasicAuth(*username, *password))
		if err != nil {
			log.Fatalf("[ERROR] Unable to connecto to Elasticsearch cluster at %v with username %v", *hostname, *username)
		}
	} else {
		client, err = elastic.NewClient(elastic.SetURL(*hostname),
						elastic.SetSniff(false),
						elastic.SetErrorLog(log.New(os.Stderr, "ELASTIC ", log.LstdFlags)))
		if err != nil {
			log.Fatalf("[ERROR] Unable to connecto to Elasticsearch cluster at %v with no authentication", *hostname)
		}
	}

	exists, err := client.IndexExists(*index).Do(context.TODO())
	if err != nil {
		log.Fatalf("[ERROR] Unable to check if the elastic index exists or not")
	}

	if exists {
		return client
	}

	if len(mapping) < 2 {
		mapping = `{"settings": {"index.mapping.total_fields.limit": 25000},
			"mappings": {"ssllabs-scan": {"dynamic_templates": [{
					"strings_as_text": {
							"match_mapping_type": "string",
							"mapping": {"type": "keyword", "ignore_above": 256, "index": true,"norms": false
					}}},{
					"number_as_date1": {
							"match_mapping_type": "long",
							"match_pattern": "regex",
							"match":   ".*not(After|Before)",
							"mapping": {
								"type": "date","format": "epoch_millis"
					}}},{
					"number_as_date2": {
							"match_mapping_type": "long",
							"match_pattern": "regex",
							"match":   ".*(start|Start|test)Time",
							"mapping": {
								"type": "date","format": "epoch_millis"
		}}}]}}}`
	}

	res, err := client.CreateIndex(*index).
			BodyString(mapping).
			Do(context.TODO())

	if err != nil {
		log.Fatal(err)
		log.Fatalf("[ERROR] Unable to create the index in elastic")
	}
	if !res.Acknowledged {
		log.Fatalf("CreateIndex was not acknowledged. Check that timeout value is correct.")
	}

	return client
}

func removeDuplicatesUnordered(elements []string) []string {
    encountered := map[string]bool{}

    // Create a map of all unique elements.
    for v:= range elements {
        encountered[elements[v]] = true
    }

    // Place all keys from the map into a slice.
    result := []string{}
    for key, _ := range encountered {
        result = append(result, key)
    }
    return result
}

func main() {
	var conf_api = flag.String("api", "BUILTIN", "API entry point, for example https://www.example.com/api/")
	var conf_elastic_host = flag.String("elastic_host", "http://127.0.0.1:9200", "Send output results to this elastic host")
	var conf_elastic_index = flag.String("elastic_index", "ssllabs-scan", "Send output results to this elastic index")
	var conf_elastic_user = flag.String("elastic_user", "", "Elasticsearch auth username")
	var conf_elastic_pwd = flag.String("elastic_pwd", "", "Elasticsearch auth password")
	var conf_elastic_mapping_file = flag.String("elastic_mapping", "", "Path to the Elasticsearch mapping file")
	var conf_grade = flag.Bool("grade", false, "Output only the hostname: grade")
	var conf_hostcheck = flag.Bool("hostcheck", false, "If true, host resolution failure will result in a fatal error.")
	var conf_hostfile = flag.String("hostfile", "", "File containing hosts to scan (one per line)")
	var conf_ignore_mismatch = flag.Bool("ignore-mismatch", false, "If true, certificate hostname mismatch does not stop assessment.")
	var conf_insecure = flag.Bool("insecure", false, "Skip certificate validation. For use in development only. Do not use.")
	var conf_quiet = flag.Bool("quiet", false, "Disable status messages (logging)")
	var conf_usecache = flag.Bool("usecache", false, "If true, accept cached results (if available), else force live scan.")
	var conf_maxage = flag.Int("maxage", 0, "Maximum acceptable age of cached results, in hours. A zero value is ignored.")
	var conf_verbosity = flag.String("verbosity", "info", "Configure log verbosity: error, notice, info, debug, or trace.")
	var conf_version = flag.Bool("version", false, "Print version and API location information and exit")
	var exclude = flag.String("exclude", "", "Exclude certain keys from the output (regex)")
	var include = flag.String("include", "", "Inluce only certain keys in the output (regex)")
	useElasticOutput = flag.Bool("elasticsearch", false, "Output results to elasticsearch server")
	conf_json_flat = flag.Bool("json-flat", false, "Output results in flattened JSON format")

	flag.Parse()

	if *conf_version {
		fmt.Println(USER_AGENT)
		fmt.Println("API location: " + apiLocation)
		return
	}

	logLevel = parseLogLevel(strings.ToLower(*conf_verbosity))

	globalIgnoreMismatch = *conf_ignore_mismatch

	if *conf_quiet {
		logLevel = LOG_NONE
	}

	// We prefer cached results
	if *conf_usecache {
		globalFromCache = true
		globalStartNew = false
	}

	if *conf_maxage != 0 {
		globalMaxAge = *conf_maxage
	}

	if *conf_grade {
		// Just the grade(s). We use flatten and RAW
		/*
			"endpoints.0.grade": "A"
			"host": "testing.spatialkey.com"
		*/
		pattern := "(host|grade)$"
		include = &pattern
		flatten := true
		conf_json_flat = &flatten
	}

	if *exclude != "" {
		exclude_pattern = regexp.MustCompile(*exclude)
		if logLevel >= LOG_DEBUG {
			log.Printf("[DEBUG] Exclude pattern: %v", *exclude)
		}
	}

	if *include != "" {
		include_pattern = regexp.MustCompile(*include)
		if logLevel >= LOG_DEBUG {
			log.Printf("[DEBUG] Include pattern: %v", *include)
		}
	}

	// Verify that the API entry point is a URL.
	if *conf_api != "BUILTIN" {
		apiLocation = *conf_api
	}

	if validateURL(apiLocation) == false {
		log.Fatalf("[ERROR] Invalid API URL: %v", apiLocation)
	}

	var hostnames []string
	if *conf_hostfile != "" {
		// Check if file is actually URL
		_, err := url.ParseRequestURI(*conf_hostfile)
		if err != nil {
		   // Open file, and read it
			var err error
			hostnames, err = readLines(conf_hostfile)
			if err != nil {
				log.Fatalf("[ERROR] Reading from specified hostfile failed: %v", err)
			}
		} else {
			var err error
			hostnames, err = downloadAndReadLines(conf_hostfile)
			if err != nil {
				log.Fatalf("[ERROR] Reading from specified hostfile failed: %v", err)
			}
		}
	} else {
		// Read hostnames from the rest of the args
		hostnames = flag.Args()
		var splitted_hostnames []string
		for _, host := range hostnames {
			splitted_hostnames = append(splitted_hostnames, strings.Fields(host)...)
		}
		hostnames = splitted_hostnames
	}
	hostnames = removeDuplicatesUnordered(hostnames)
	if logLevel >= LOG_DEBUG {
		log.Printf("[DEBUG] %d domain(s) found in specified input...", len(hostnames))
	}


	if *conf_hostcheck {
		// Validate all hostnames before we attempt to test them. At least
		// one hostname is required.
		for _, host := range hostnames {
			if validateHostname(host) == false {
				log.Fatalf("[ERROR] Invalid hostname: %v", host)
			}
		}
	}

	if *conf_insecure {
		globalInsecure = *conf_insecure
	}

	if *useElasticOutput {
		mapping := ""
		if len(*conf_elastic_mapping_file) > 0 {
			content, err := ioutil.ReadFile(*conf_elastic_mapping_file)
			if err != nil {
				log.Fatal(err)
			}
			mapping = string(content)
		}
		elasticIndex = *conf_elastic_index
		elasticClient = ConnectToElastic(conf_elastic_host, conf_elastic_index, conf_elastic_user, conf_elastic_pwd, mapping)
	}

	hp := NewHostProvider(hostnames)
	manager := NewManager(hp)

	// Respond to events until all the work is done.
	for {
		_, running := <-manager.FrontendEventChannel
		if running == false {
			var results []byte
			var err error

			if hp.StartingLen == 0 {
				return
			}

			if *conf_json_flat {
				// Flat JSON and RAW
				for i := range manager.results.responses {
					results := manager.results.responses[i]

					// Print the flattened data
					fmt.Println(results)
				}
			} else {
				// Raw (non-Go-mangled) JSON output
				fmt.Println("[")
				for i := range manager.results.responses {
					results := manager.results.responses[i]

					if i > 0 {
						fmt.Println(",")
					}
					fmt.Println(results)
				}
				fmt.Println("]")
			}

			if err != nil {
				log.Fatalf("[ERROR] Output to JSON failed: %v", err)
			}

			fmt.Println(string(results))

			if logLevel >= LOG_INFO {
				log.Println("[INFO] All assessments complete; shutting down")
			}

			return
		}
	}
}
