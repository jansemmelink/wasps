package main

import (
	"context"
	"encoding"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/go-msvc/errors"
	"github.com/gorilla/mux"
	"github.com/jansemmelink/wasps/lib/db"
	"github.com/jansemmelink/wasps/lib/wasps"
	"github.com/stewelarend/logger"
)

var log = logger.New().WithLevel(logger.LevelDebug)

var (
	waspsStore wasps.Wasps
)

func main() {
	port := os.Getenv("HTTP_SERVER_PORT")
	if port == "" {
		port = "19081"
	}

	db, err := db.New("wasps")
	if err != nil {
		panic(err)
	}
	waspsStore, err = wasps.New(db)
	if err != nil {
		panic(err)
	}
	r := mux.NewRouter()

	r.HandleFunc("/wasps", handler(waspsList)).Methods(http.MethodGet)
	r.HandleFunc("/wasps", handler(waspsAdd)).Methods(http.MethodPost)
	r.HandleFunc("/wasp/{id}", handler(waspGet)).Methods(http.MethodGet)
	// r.HandleFunc("/wasp/{id}", handler(waspUpd)).Methods(http.MethodPut)
	// r.HandleFunc("/wasp/{id}", handler(waspDel)).Methods(http.MethodDelete)
	// r.HandleFunc("/wasps/count", handler(waspsCount)).Methods(http.MethodGet)
	r.HandleFunc("/wasp/login", handler(waspLogin)).Methods(http.MethodGet)

	// r.HandleFunc("/organisations", handler(organisationsList)).Methods(http.MethodGet)
	// r.HandleFunc("/organisations", handler(organisationsAdd)).Methods(http.MethodPost)
	// r.HandleFunc("/organisation/{id}", handler(organisationGet)).Methods(http.MethodGet)
	// r.HandleFunc("/organisation/{id}", handler(organisationUpd)).Methods(http.MethodPut)
	// r.HandleFunc("/organisation/{id}", handler(organisationDel)).Methods(http.MethodDelete)
	// r.HandleFunc("/organisation/{id}/addr_list", handler(organisationAddrList)).Methods(http.MethodGet)
	// r.HandleFunc("/organisations/count", handler(organisationsCount)).Methods(http.MethodGet)

	// r.HandleFunc("/query_quota", handler(queryQuota)).Methods(http.MethodGet)

	// r.HandleFunc("/get_hosts", handler(getHosts)).Methods(http.MethodGet)

	http.Handle("/", r)
	http.ListenAndServe(":"+port, nil)
}

type ErrorResponse struct {
	Error string `json:"error"`
}

type Validator interface {
	Validate() error
}

type ErrorWithCode interface {
	error
	Code() int
}

type WaspsStore struct{}

func handler(handlerFunc interface{}) func(http.ResponseWriter, *http.Request) {
	funcValue := reflect.ValueOf(handlerFunc)
	if funcValue.Kind() != reflect.Func {
		panic(errors.Errorf("handler is not a func"))
	}
	funcType := funcValue.Type()
	if funcType.NumIn() != 2 || funcType.NumOut() != 2 {
		panic(errors.Errorf("handler is not func(ctx, req) (res, err)"))
	}
	if funcType.In(0) != reflect.TypeOf((*context.Context)(nil)).Elem() {
		panic(errors.Errorf("handler is not func(%v, req) (res, err) must take context.Context as first arg", funcType.In(0)))
	}
	if funcType.Out(1) != reflect.TypeOf((*error)(nil)).Elem() {
		panic(errors.Errorf("handler is not func(ctx, req) (res, %v) must return error as last result", funcType.Out(1)))
	}
	reqType := funcType.In(1)
	//resType := funcType.Out(0)

	return func(httpRes http.ResponseWriter, httpReq *http.Request) {
		code := http.StatusInternalServerError
		var err error
		var res interface{}
		defer func() {
			if r := recover(); r != nil {
				err = errors.Errorf("Handler crashed: %+v", r)
				log.Errorf("Handler crashed: %+v", err)
			}

			httpRes.Header().Set("Content-Type", "application/json")
			httpRes.WriteHeader(code)

			var jsonRes []byte
			if code != http.StatusOK {
				errRes := ErrorResponse{}
				if err != nil {
					errRes.Error = fmt.Sprintf("%+v", err)
				} else {
					errRes.Error = "failed"
				}
				jsonRes, _ = json.Marshal(errRes)
				log.Errorf("Handler error: %+v", err)
			} else {
				//success
				jsonRes, _ = json.Marshal(res)
				log.Debugf("Handler success")
			}
			fmt.Fprintln(httpRes, string(jsonRes))
		}()

		log.Debugf("HTTP %s %s", httpReq.Method, httpReq.URL.Path)

		//prepare request:
		//  parse body into req
		//  apply params into the req (overwrite selected fields)
		//  apply path params into the req (overwrite selected fields)
		reqPtrValue := reflect.New(reqType)
		if httpReq.Body != nil {
			if err = json.NewDecoder(httpReq.Body).Decode(reqPtrValue.Interface()); err != nil && err != io.EOF {
				err = errors.Wrapf(err, "failed to decode body into request type %v", reqType)
				code = http.StatusBadRequest
				return
			}
		}

		if reqType.Kind() == reflect.Struct {
			for paramName, paramValue := range httpReq.URL.Query() {
				if len(paramValue) > 1 {
					err = errors.Errorf("multiple values not allowed for URL param %s=%+v", paramName, paramValue)
					code = http.StatusBadRequest
					return
				}

				applied := false
				for i := 0; i < reqType.NumField(); i++ {
					fieldName := strings.SplitN(reqType.Field(i).Tag.Get("json"), ",", 2)[0]
					if paramName == fieldName {
						log.Debugf("Set param %s=%s", paramName, paramValue)
						fieldPtrValue := reflect.New(reqType.Field(i).Type)
						if unmarshaller, ok := fieldPtrValue.Interface().(encoding.TextUnmarshaler); ok {
							if err = unmarshaller.UnmarshalText([]byte(paramValue[0])); err != nil {
								err = errors.Wrapf(err, "cannot unmarshal param %s=%s into %v", paramName, paramValue[0], reqType.Field(i).Type)
								code = http.StatusBadRequest
								return
							}
						} else {
							//no unmarshal - try to set
							switch reqType.Field(i).Type.Kind() {
							case reflect.String:
								reqPtrValue.Elem().Field(i).Set(reflect.ValueOf(paramValue[0]))
							case reflect.Int64, reflect.Int32, reflect.Int16, reflect.Int8, reflect.Int:
								var i64 int64
								if i64, err = strconv.ParseInt(paramValue[0], 10, 64); err != nil {
									err = errors.Wrapf(err, "paran %s=%s must be an integer value", paramName, paramValue)
									code = http.StatusBadRequest
									return
								} else {
									switch reqType.Field(i).Type.Kind() {
									case reflect.Int64:
										reqPtrValue.Elem().Field(i).Set(reflect.ValueOf(i64))
									case reflect.Int32:
										reqPtrValue.Elem().Field(i).Set(reflect.ValueOf(int32(i64)))
									case reflect.Int16:
										reqPtrValue.Elem().Field(i).Set(reflect.ValueOf(int16(i64)))
									case reflect.Int8:
										reqPtrValue.Elem().Field(i).Set(reflect.ValueOf(int8(i64)))
									case reflect.Int:
										reqPtrValue.Elem().Field(i).Set(reflect.ValueOf(int(i64)))
									}
								}
							case reflect.Float64, reflect.Float32:
								var f64 float64
								if f64, err = strconv.ParseFloat(paramValue[0], 64); err != nil {
									err = errors.Wrapf(err, "paran %s=%s must be a number", paramName, paramValue)
									code = http.StatusBadRequest
									return
								} else {
									switch reqType.Field(i).Type.Kind() {
									case reflect.Float64:
										reqPtrValue.Elem().Field(i).Set(reflect.ValueOf(f64))
									case reflect.Float32:
										reqPtrValue.Elem().Field(i).Set(reflect.ValueOf(float32(f64)))
									}
								}
							default:
								err = errors.Wrapf(err, "paran %s type %v must be specified in the body", paramName, reqType.Field(i).Type)
								code = http.StatusBadRequest
								return
							}
						}
						log.Debugf("Defined %s=%s in request: %+v", paramName, paramValue[0], reqPtrValue.Elem().Interface())
						applied = true
						break
					}
				}
				if !applied {
					err = errors.Errorf("unknown param(%s)", paramName)
					code = http.StatusBadRequest
					return
				}
			}
		}

		//validate the final request
		if validator, ok := reqPtrValue.Interface().(Validator); ok {
			if err = validator.Validate(); err != nil {
				err = errors.Wrapf(err, "invalid request", reqType)
				code = http.StatusBadRequest
				return
			}
		}

		ctx, cancelFunc := context.WithTimeout(context.Background(), time.Second)
		defer func() {
			log.Debugf("end of context: err=%+v", ctx.Err())
			cancelFunc()
		}()

		ctx = context.WithValue(ctx, WaspsStore{}, waspsStore)

		select {
		case <-func() chan bool {
			ch := make(chan bool)
			go func(ch chan bool) {
				args := []reflect.Value{
					reflect.ValueOf(ctx),
					reqPtrValue.Elem(),
				}
				results := funcValue.Call(args)

				var ok bool
				if err, ok = results[1].Interface().(error); ok && err != nil {
					log.Debugf("err = %+v", err)
					if errWithCode, ok := err.(ErrorWithCode); ok {
						code = errWithCode.Code()
					}
				} else {
					res = results[0].Interface()
					err = nil
					code = http.StatusOK
					log.Debugf("success: %+v", res)
				}
				ch <- true
			}(ch)
			return ch
		}():
			log.Debugf("Call returned")

		case <-ctx.Done():
			err = errors.Errorf("handler took too long")
			code = http.StatusRequestTimeout
			return
		}

		log.Debugf("Done")

		//request := ""
		//requestParams := map[string]interface{}
		//operationParams = {}
		//file_download = 0

		// if file_download == 0:
		// 	# Add body into callback it specified
		// 	if 'callback' in requestParams:
		// 		body = ('%s(%s);' % (requestParams['callback'], body))
		// 	# Printout response body for debugging
		// 	logger.debug('Response:')
		// 	logger.debug(body)

		// 	# Send Http response
		// 	self.send_response(200)
		// 	self.send_header('Content-Type', 'text/plain')
		// 	self.send_header('Content-Length', len(body))
		// 	self.send_header('Expires', '-1')
		// 	self.send_header('Cache-Control', 'no-cache')
		// 	self.send_header('Pragma', 'no-cache')
		// 	self.end_headers()

		// 	self.wfile.write(body)
		// 	self.wfile.flush()

		// 	# Close Connection
		// 	self.connection.shutdown(1)

		// except Exception as e:
		// 	# pass
		// 	logger.error(e)
		// 	self.send_error(500, 'Internal Error %s' % (str(e)))
		// 	code = 1
		// 	description = ('Failed:  %s' % (str(e)))
		// 	description = description.replace('"', '').strip()
		// 	response = '{"code":%d,"desc":"%s"}' % (code, description)
		// 	return response

		// 	if file_download == 0:

		// 		# Send Http response
		// 		mime_type = 'text/json'
		// 		self.send_response(200)
		// 		self.send_header('Access-Control-Allow-Origin', '*')
		// 		if file_upload == 1:
		// 			mime_type = 'text/html'

		// 		self.send_header('Content-Type', mime_type)
		// 		self.send_header('Content-Length', len(body))
		// 		self.send_header('Expires', '-1')
		// 		self.send_header('Cache-Control', 'no-cache')
		// 		self.send_header('Pragma', 'no-cache')
		// 		self.end_headers()
		// 		self.wfile.write(body)
		// 		self.wfile.flush()

		// 		# Close Connection
		// 		self.connection.shutdown(1)

		// except Exception as e:
		// 	# pass
		// 	logger.error(e)
		// 	self.send_error(500, 'Internal Error %s' % (str(e)))
		// 	code = 1
		// 	description = ('Failed:  %s' % (str(e)))
		// 	description = description.replace('"', '').strip()
		// 	response = '{"code":%d,"desc":"%s"}' % (code, description)
		// 	return response
	}
}

func ErrorCode(code int, err error) ErrorWithCode {
	return errorWithCode{
		error: err,
		code:  code,
	}
}

type errorWithCode struct {
	error
	code int
}

func (e errorWithCode) Code() int { return e.code }

type WaspsListReq struct{}

func waspsList(ctx context.Context, req WaspsListReq) ([]wasps.Wasp, error) {
	wasps := ctx.Value(WaspsStore{}).(wasps.Wasps)
	filter := map[string]interface{}{}
	list := wasps.Find(filter)
	return list, nil
}

func waspsAdd(ctx context.Context, newWasp wasps.Wasp) (addedWasp wasps.Wasp, err error) {
	if err = newWasp.Validate(); err != nil {
		err = ErrorCode(http.StatusBadRequest, errors.Wrapf(err, "invalid wasp"))
		return
	}
	wasps := ctx.Value(WaspsStore{}).(wasps.Wasps)
	if addedWasp, err = wasps.Add(newWasp); err != nil {
		err = ErrorCode(http.StatusInternalServerError, errors.Wrapf(err, "failed to store new wasp"))
		return
	}
	return
}

type OnlyID struct {
	ID string `json:"id"`
}

func (o OnlyID) Validate() error {
	if o.ID == "" {
		return errors.Errorf("missing id")
	}
	return nil
}

func waspGet(ctx context.Context, req OnlyID) (wasp wasps.Wasp, err error) {
	ww := ctx.Value(WaspsStore{}).(wasps.Wasps)
	if w := ww.Get(req.ID); w == nil {
		return wasps.Wasp{}, ErrorCode(http.StatusNotFound, errors.Errorf("no found"))
	} else {
		return *w, nil
	}
}

func waspUpd()    {}
func waspDel()    {}
func waspsCount() {}

type LoginReq struct {
	User string      `json:"user"`
	Pass string      `json:"pass"`
	Type string      `json:"type"`
	Json wasps.YesNo `json:"json"`
}

func waspLogin(ctx context.Context, req LoginReq) (wasps.Wasp, error) {
	log.Debugf("Login %+v", req)
	// paramUser := httpReq.URL.Query().Get("user")
	// paramPass := httpReq.URL.Query().Get("pass")
	// paramType := httpReq.URL.Query().Get("type")
	// paramJson := httpReq.URL.Query().Get("json")

	// db.Query("SELECT ")

	// http.Error(httpRes, "NYI", http.StatusNotFound)
	return wasps.Wasp{}, errors.Errorf("NYI")
}

func organisationsList()    {}
func organisationsAdd()     {}
func organisationGet()      {}
func organisationUpd()      {}
func organisationDel()      {}
func organisationAddrList() {}
func organisationsCount()   {}
func queryQuota()           {}
func getHosts()             {}

// #Only performed on MAIN_NGF_TCPS_PORT
// def m_r_rest_login(requestParams):
//     logger.debug('Login')
//     url = "http://%s:%s/wasp/login?user=%s&pass=%s&type=%s&json=yes" % (
//         MAIN_NGF_TCPS_IP, MAIN_NGF_TCPS_PORT, requestParams["user"], requestParams["pass"], requestParams["type"])
//     # Get repsponse from server.
//     response = urllib2.urlopen(url).read()
//     logger.debug(response)

//     response_dict = json.loads(response)
//     m_r_format_response(response_dict)
//     m_r_log_transaction(requestParams["user"], "login", requestParams["user"], "Login Request:", response_dict['code'],
//                         response_dict['desc'])
//     # 	m_r_format_response (response["desc"], response["detail"])
//     return json.dumps(response_dict)

// #Only performed on MAIN_NGF_TCPS_PORT
// def m_r_rest_get_wasp(requestParams):
//     logger.debug('m_r_rest_get_wasp')
//     code = SUCCESS_CODE
//     description = ''

//     url = "http://%s:%s/wasp/get?id=%s&json=yes" % (MAIN_NGF_TCPS_IP, MAIN_NGF_TCPS_PORT, requestParams["id"])

//     response = urllib2.urlopen(url).read()

//     response_dict = json.loads(response)
//     m_r_format_response(response_dict)
//     logger.debug(response)
//     return response

// #Only performed on MAIN_NGF_TCPS_PORT
// def m_r_rest_list_wasp(requestParams):
//     logger.debug('m_r_rest_list_wasp')
//     code = SUCCESS_CODE
//     description = ''
//     url = ''
//     filter = ''
//     try:
//         filter = requestParams['filter'];
//     except Exception as e:
//         filter = ''

//     filter_org = ''
//     try:
//         filter_org = requestParams['filter_org'];
//     except Exception as e:
//         filter_org = ''

//     start = 0
//     try:
//         start = int(requestParams['start']);
//     except Exception as e:
//         start = 0

//     limit = 100
//     try:
//         limit = int(requestParams['limit']);
//     except Exception as e:
//         limit = 100

//     org_exact_match = 0
//     try:
//         org_exact_match = int(requestParams['org_exact_match']);
//     except Exception as e:
//         org_exact_match = 0

//     try:
//         url = "http://%s:%s/wasp/list?org_exact_match=%d&start=%d&limit=%d&filter=%s&filter_org=%s&json=yes" % (
//             MAIN_NGF_TCPS_IP, MAIN_NGF_TCPS_PORT, org_exact_match, start, limit, filter, filter_org)
//         logger.debug(url)
//         response = urllib2.urlopen(url).read()
//     except Exception as e:
//         response = "Could not list wasps"

//     # Get repsponse from server.
//     logger.debug(response)
//     return response

// def m_r_rest_add_wasp(self, requestParams):
//     logger.debug("m_r_rest_add_wasp")
//     response = ""
//     # 	length = int(self.headers.getheader('content-length'))
//     # 	postvars = urlparse.parse_qs(self.rfile.read(length), keep_blank_values=1)
//     # 	logger.debug('Post: %s' % postvars;
//     # Parse the form data posted
//     form = cgi.FieldStorage(
//         fp=self.rfile,
//         headers=self.headers,
//         environ={'REQUEST_METHOD': 'POST',
//                  'CONTENT_TYPE': self.headers['Content-Type']
//                  })

//     logger.debug(form['wasp'].value)

//     query_params = "/wasp/add?json=yes"
//     response_dict = m_r_push_to_nodes(nodes=requestParams['nodes'],query_params=query_params,query_data=form['wasp'].value)

//     m_r_format_response(response_dict)
//     return json.dumps(response_dict)

// def m_r_rest_del_wasp(requestParams):
//     logger.debug('m_r_del_wasp')
//     code = SUCCESS_CODE
//     description = ''

//     logger.debug (requestParams)

//     query_params = "/wasp/del?id=%s&json=yes" % requestParams["id"]
//     response_dict = m_r_push_to_nodes(nodes=requestParams['nodes'],query_params=query_params)

//     m_r_log_transaction(requestParams["user"], "delete", requestParams["id"], "Delete Request: Wasp",
//                         response_dict["code"], response_dict["desc"])
//     m_r_format_response(response_dict)
//     return json.dumps(response_dict)

// #Only performed on MAIN_NGF_TCPS_PORT
// def m_r_rest_count_wasp(requestParams):
//     logger.debug('m_r_count_wasp')
//     code = SUCCESS_CODE
//     description = ''
//     url = ''

//     filter = ''
//     try:
//         filter = requestParams['filter'];
//     except Exception as e:
//         filter = ''

//     filter_org = ''
//     try:
//         filter_org = requestParams['filter_org'];
//     except Exception as e:
//         filter_org = ''

//     url = "http://%s:%s/wasp/count?filter=%s&filter_org=%s&json=yes" % (MAIN_NGF_TCPS_IP, MAIN_NGF_TCPS_PORT, filter, filter_org)

//     # Get repsponse from server.
//     response = urllib2.urlopen(url).read()
//     logger.debug(response)
//     return response

// def m_r_rest_upd_wasp(self, requestParams):
//     logger.debug("m_r_upd_wasp")
//     response = ""
//     # 	length = int(self.headers.getheader('content-length'))
//     # 	postvars = urlparse.parse_qs(self.rfile.read(length), keep_blank_values=1)
//     # 	logger.debug('Post: %s' % postvars;
//     # Parse the form data posted
//     form = cgi.FieldStorage(
//         fp=self.rfile,
//         headers=self.headers,
//         environ={'REQUEST_METHOD': 'POST',
//                  'CONTENT_TYPE': self.headers['Content-Type']
//                  })
//     # 	logger.debug(url

//     logger.debug(form['wasp'].value)
//     query_params = "/wasp/upd?json=yes"
//     response_dict = m_r_push_to_nodes(nodes=requestParams['nodes'],query_params=query_params,query_data=form['wasp'].value)

//     #	Log the transaction to be traced later.
//     req_description = "Update request: %s"
//     if requestParams["pass_ch"] == "1":
//         req_description = req_description % "Password Changed"
//     else:
//         req_description = req_description % "User Update"

//     m_r_log_transaction(requestParams["user"], "update", requestParams["req_user"], req_description,
//                         response_dict["code"], response_dict["desc"])
//     m_r_format_response(response_dict)
//     return json.dumps(response_dict)

// def m_r_rest_add_org(self, requestParams):
//     logger.debug("m_r_rest_add_org")
//     response = ""
//     # 	length = int(self.headers.getheader('content-length'))
//     # 	postvars = urlparse.parse_qs(self.rfile.read(length), keep_blank_values=1)
//     # 	logger.debug('Post: %s' % postvars;
//     # Parse the form data posted
//     form = cgi.FieldStorage(
//         fp=self.rfile,
//         headers=self.headers,
//         environ={'REQUEST_METHOD': 'POST',
//                  'CONTENT_TYPE': self.headers['Content-Type']
//                  })

//     logger.debug(form['organisation'].value)

//     query_params = "/organisation/add?json=yes"
//     response_dict = m_r_push_to_nodes(nodes=requestParams['nodes'],query_params=query_params,query_data=form['organisation'].value)

//     m_r_format_response(response_dict)
//     return json.dumps(response_dict)

// def m_r_rest_upd_org(self, requestParams):
//     logger.debug("m_r_rest_upd_org")
//     response = ""
//     url = "http://localhost:%s/organisation/upd?json=yes" % MAIN_NGF_TCPS_PORT

//     # Parse the form data posted
//     form = cgi.FieldStorage(
//         fp=self.rfile,
//         headers=self.headers,
//         environ={'REQUEST_METHOD': 'POST',
//                  'CONTENT_TYPE': self.headers['Content-Type']
//                  })

//     logger.debug(form['organisation'].value)
//     query_params = "/organisation/upd?json=yes"
//     response_dict = m_r_push_to_nodes(nodes=requestParams['nodes'],query_params=query_params,query_data=form['organisation'].value)

//     #	Log the transaction to be traced later.
//     req_description = "Update request: %s"
//     if requestParams["pass_ch"] == "1":
//         req_description = req_description % "Password Changed"
//     else:
//         req_description = req_description % "User Update"

//     m_r_log_transaction(requestParams["user"], "update", requestParams["req_user"], req_description,
//                         response_dict["code"], response_dict["desc"])
//     m_r_format_response(response_dict)
//     return json.dumps(response_dict)

// #Only performed on MAIN_NGF_TCPS_PORT
// def m_r_rest_get_org(requestParams):
//     logger.debug('m_r_rest_get_org')
//     code = SUCCESS_CODE
//     description = ''
//     url = "http://%s:%s/organisation/get?id=%s&json=yes" % (MAIN_NGF_TCPS_IP, MAIN_NGF_TCPS_PORT, requestParams["id"])
//     # Get repsponse from server.
//     response = urllib2.urlopen(url).read()
//     logger.debug(response)
//     return response

// #Only performed on MAIN_NGF_TCPS_PORT
// def m_r_rest_get_org_addr_list(requestParams):
//     logger.debug('m_r_rest_get_org_addr_list')
//     code = SUCCESS_CODE
//     description = ''
//     url = "http://%s:%s/organisation/addr_list?id=%s&json=yes" % (MAIN_NGF_TCPS_IP, MAIN_NGF_TCPS_PORT, requestParams["id"])
//     # Get repsponse from server.
//     response = urllib2.urlopen(url).read()
//     logger.debug(response)
//     return response

// #Only performed on MAIN_NGF_TCPS_PORT
// def m_r_rest_list_org(requestParams):
//     logger.debug('m_r_rest_list_org')
//     code = SUCCESS_CODE
//     description = ''
//     url = ''
//     try:
//         filter = requestParams['filter'];
//         url = "http://%s:%s/organisation/list?start=%s&limit=%s&filter=%s&json=yes" % (
//             MAIN_NGF_TCPS_IP, MAIN_NGF_TCPS_PORT, requestParams['start'], requestParams['limit'], filter)
//     except Exception as e:
//         try:
//             url = "http://%s:%s/organisation/list?start=%s&limit=%s&json=yes" % (
//                 MAIN_NGF_TCPS_IP, MAIN_NGF_TCPS_PORT, requestParams['start'], requestParams['limit'])
//         except Exception as e:
//             url = "http://%s:%s/organisation/list?start=%s&limit=%s&json=yes" % (MAIN_NGF_TCPS_IP, MAIN_NGF_TCPS_PORT, '0', '150')

//     # Get repsponse from server.
//     logger.debug(url)
//     response = urllib2.urlopen(url).read()
//     logger.debug(response)
//     return response

// # Constants
// SCRIPT_DIR = os.path.dirname(__file__) + '/'
// CONFIG_FILE = SCRIPT_DIR + 'properties/wasp_config.cfg'
// CONFIG_SECTION = 'wasp_config_gui'
// SUCCESS_CODE = 0
// MAIN_NGF_TCPS_IP = 'localhost'#Will be set via index[0] of NGF_TCPS_IPS_CSV
// MAIN_NGF_TCPS_PORT = '9300'#Will be set via index[0] of NGF_TCPS_PORTS_CSV

// # Global Vars
// # Config Params with defaults
// LOG_LEVEL = logging.DEBUG
// LOG_MAX_SIZE = 1 * 1000000  # 1Mb
// TIMEOUT_DURATION = 5
// HTTP_SERVER_PORT = 9093
// NGF_TCPS_PORTS = []
// NGF_TCPS_IPS = []
// NGF_TCPS_NODE_NAMES = []
// DB_NAME = ''
// WASP_NAME = 'Wasp'
// ORG_NAME = 'Organisation'
// PIDFILE="/tmp/.WaspConfigServer.pid"
// HOSTNAME = socket.gethostname()

// # Defined Functions
// # Each function handles a certain HTTP request and returns the
// # appropriate response string to be added to the body

// # Functions used internally:
// # These are used by the m_r_rest_* functions
// def m_r_load_config():
//     global LOG_LEVEL
//     global LOG_MAX_SIZE
//     global TIMEOUT_DURATION
//     global HTTP_SERVER_PORT
//     global NGF_TCPS_PORTS
//     global NGF_TCPS_IPS
//     global NGF_TCPS_NODE_NAMES
//     global DB_NAME
//     global WASP_NAME
//     global ORG_NAME
//     global PIDFILE
//     global MAIN_NGF_TCPS_IP
//     global MAIN_NGF_TCPS_PORT

//     try:
//         logger.info("Getting config_file: %s", CONFIG_FILE)
//         config = ConfigParser.RawConfigParser()
//         config.read(CONFIG_FILE)
//         if config.has_section(CONFIG_SECTION):
//             logger.info("Found section: %s", CONFIG_SECTION)
//             # LOGGING
//             if config.get(CONFIG_SECTION, 'log_level') == 'DEBUG':
//                 LOG_LEVEL = logging.DEBUG;
//             elif config.get(CONFIG_SECTION, 'log_level') == 'INFO':
//                 LOG_LEVEL = logging.INFO;
//             elif config.get(CONFIG_SECTION, 'log_level') == 'ERROR':
//                 LOG_LEVEL = logging.ERROR;
//             elif config.get(CONFIG_SECTION, 'log_level') == 'CRITICAL':
//                 LOG_LEVEL = logging.CRITICAL;
//             if config.has_option(CONFIG_SECTION, 'log_level'):
//                 pass
//             else:
//                 LOG_LEVEL = logging.DEBUG;

//             logger.info("Log level = %s", config.get(CONFIG_SECTION, 'log_level'))

//             if config.has_option(CONFIG_SECTION, 'log_max_size'):
//                 LOG_MAX_SIZE = config.getint(CONFIG_SECTION, 'log_max_size') * 1000000

//             logger.info("log_max_size = %s", config.get(CONFIG_SECTION, 'log_max_size'))
//             # TIMEOUT
//             if config.has_option(CONFIG_SECTION, 'timeout_dur'):
//                 TIMEOUT_DURATION = config.getint(CONFIG_SECTION, 'timeout_dur')

//             logger.info("timeout_dur = %s", config.get(CONFIG_SECTION, 'timeout_dur'))
//             # PORTS
//             # THIS SERVER
//             if config.has_option(CONFIG_SECTION, 'http_server_port'):
//                 HTTP_SERVER_PORT = config.getint(CONFIG_SECTION, 'http_server_port')
//             else:
//                 raise AttributeError("\"http_server_port\" not specified in \"%s\" under section \"%s\"", CONFIG_FILE,
//                                      CONFIG_SECTION)

//             logger.info("http_server_port = %s", config.get(CONFIG_SECTION, 'http_server_port'))

//             # ngf_tcps_ports_csv
//             if config.has_option(CONFIG_SECTION, 'ngf_tcps_ports_csv'):
//                 tcps_ports_csv = config.get(CONFIG_SECTION, 'ngf_tcps_ports_csv')
//                 NGF_TCPS_PORTS = [int(x) for x in tcps_ports_csv.split(',')]
//             else:
//                 raise AttributeError("\"ngf_tcps_ports_csv\" not specified in \"%s\" under section \"%s\"", CONFIG_FILE,
//                                      CONFIG_SECTION)

//             for i,port in enumerate(NGF_TCPS_PORTS):
//                 logger.info("ngf_tcps_port[%d] = %d", i,port)

//             # ngf_tcps_ips_csv
//             if config.has_option(CONFIG_SECTION, 'ngf_tcps_ips_csv'):
//                 tcps_ips_csv = config.get(CONFIG_SECTION, 'ngf_tcps_ips_csv')
//                 NGF_TCPS_IPS = tcps_ips_csv.split(',')
//             else:
//                 raise AttributeError("\"ngf_tcps_ips_csv\" not specified in \"%s\" under section \"%s\"", CONFIG_FILE,
//                                      CONFIG_SECTION)

//             for i,ip in enumerate(NGF_TCPS_IPS):
//                 logger.info("ngf_tcps_ip[%d] = %s", i,ip)
//             #
//             # if len(NGF_TCPS_IPS) != len(set(NGF_TCPS_IPS)):
//             #     raise AttributeError("Duplicate IP's detected, the WaspConfig doesn't yet support more than 1 node per host.")

//             if (len(NGF_TCPS_PORTS) != len (NGF_TCPS_IPS)):
//                 raise AttributeError("Number of IPS and PORTS have to be the same")

//             MAIN_NGF_TCPS_IP = NGF_TCPS_IPS[0]
//             MAIN_NGF_TCPS_PORT = NGF_TCPS_PORTS[0]

//             logger.debug("Main NGF_TCPS_HOST=http://%s:%d", MAIN_NGF_TCPS_IP, MAIN_NGF_TCPS_PORT)

//             # ngf_tcps_nodenames_csv
//             if config.has_option(CONFIG_SECTION, 'ngf_tcps_nodenames_csv'):
//                 tcps_nodenames_csv = config.get(CONFIG_SECTION, 'ngf_tcps_nodenames_csv')
//                 NGF_TCPS_NODE_NAMES = tcps_nodenames_csv.split(',')
//             else:
//                 raise AttributeError("\"ngf_tcps_nodenames_csv\" not specified in \"%s\" under section \"%s\"", CONFIG_FILE,
//                                      CONFIG_SECTION)

//             for i,name in enumerate(NGF_TCPS_NODE_NAMES):
//                 logger.info("ngf_tcps_nodes[%d] = %s", i,name)

//             if (len(NGF_TCPS_PORTS) != len (NGF_TCPS_NODE_NAMES)):
//                 raise AttributeError("Number of IPS,PORTS and NODENAMES have to be the same.")

//             for i,name in enumerate(NGF_TCPS_NODE_NAMES):
//                 logger.info("%s = %s:%s", name,NGF_TCPS_IPS[i], NGF_TCPS_PORTS[i])

//             if len(NGF_TCPS_NODE_NAMES) != len(set(NGF_TCPS_NODE_NAMES)):
//                 raise AttributeError("Duplicate ngf_tcps_nodenames detected.")

//             # Database
//             if config.has_option(CONFIG_SECTION, 'db_name'):
//                 DB_NAME = config.get(CONFIG_SECTION, 'db_name')
//             else:
//                 raise AttributeError(
//                     "\"db_name\" not specified in \"%s\" under section \"%s\"" % (CONFIG_FILE, CONFIG_SECTION))

//             logger.info("db_name = %s", config.get(CONFIG_SECTION, 'db_name'))

//             # PIDFILE
//             if config.has_option(CONFIG_SECTION, 'pidfile'):
//                 PIDFILE = config.get(CONFIG_SECTION, 'pidfile')
//             else:
//                 raise AttributeError(
//                     "\"pidfile\" not specified in \"%s\" under section \"%s\"" % (CONFIG_FILE, CONFIG_SECTION))

//             logger.info("pidfile = %s", config.get(CONFIG_SECTION, 'pidfile'))

//             # Naming
//             if config.has_option(CONFIG_SECTION, 'wasp_name'):
//                 WASP_NAME = config.get(CONFIG_SECTION, 'wasp_name')
//             else:
//                 raise AttributeError(
//                     "\"wasp_name\" not specified in \"%s\" under section \"%s\"" % (CONFIG_FILE, CONFIG_SECTION))

//             logger.info("wasp_name = %s", config.get(CONFIG_SECTION, 'wasp_name'))

//             if config.has_option(CONFIG_SECTION, 'org_name'):
//                 ORG_NAME = config.get(CONFIG_SECTION, 'org_name')
//             else:
//                 raise AttributeError(
//                     "\"org_name\" not specified in \"%s\" under section \"%s\"" % (CONFIG_FILE, CONFIG_SECTION))

//             logger.info("org_name = %s", config.get(CONFIG_SECTION, 'org_name'))

//             return SUCCESS_CODE
//     except Exception as e:
//         logger.critical("Config not loaded: %s", str(e))
//         return -1

// def m_r_db_connect():
//     # Open database connection
//     db = MySQLdb.connect("127.0.0.1", "ngf_user", "ngf_user", DB_NAME, local_infile=1)
//     return db

// # PURPOSE:
// #
// #  Set up logging for transactions
// def m_r_setup_transaction_logging():
//     logger.debug("m_r_setup_transaction_logging")
//     db = m_r_db_connect()

//     cursor = db.cursor()

//     try:
//         query = "SHOW TABLES LIKE \'nfe_wasp_config_transactions\';"
//         cursor.execute(query)
//         result = cursor.fetchone()

//         if result:
//             logger.debug("The table \'nfe_wasp_config_transactions\' already exists. Don't need to create.")
//         else:
//             query = """CREATE TABLE IF NOT EXISTS nfe_wasp_config_transactions(
//             id              INT(11) NOT NULL PRIMARY KEY AUTO_INCREMENT,
//             time            TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
//             user			varchar(64) NOT NULL,
//             request_type	varchar(32) NOT NULL,
//             request_user	varchar(64) NOT NULL,
//             request_desc	varchar(128),
//             result_code		INT(11) NOT NULL,
//             result_desc		varchar(128)
//             ) ENGINE=InnoDB DEFAULT CHARSET=utf8;
//             """
//             logger.debug(query)
//             try:
//                 cursor.execute(query)
//                 result = cursor.fetchone()
//                 logger.debug(result)
//             except Exception as e:
//                 logger.error(e)

//     except Exception as e:
//         logger.error(e)

//     return;

// def m_r_new_generic_response_json(code, desc, detail):
//     resp_dict = {
//         "code": code,
//         "desc": desc,
//         "detail": detail,
//     }
//     return json.dumps(resp_dict)

// # Format responses to show correct naming which customers use. NOt the generic WASP or ORG
// def m_r_format_response(p_response_dict):
//     try:
//         if p_response_dict["desc"] != "":
//             p_response_dict["desc"] = p_response_dict["desc"].replace("WASP", WASP_NAME)
//             p_response_dict["desc"] = p_response_dict["desc"].replace("ORGANISATION", ORG_NAME)
//     except Exception as e:
//         logger.debug(e)

//     try:
//         if p_response_dict["detail"] != undefined:
//             if p_response_dict["detail"] != "":
//                 p_response_dict["detail"] = p_response_dict["detail"].replace("WASP", WASP_NAME)
//                 p_response_dict["detail"] = p_response_dict["detail"].replace("ORGANISATION", ORG_NAME)
//     except Exception as e:
//         logger.debug(e)
//     return 0;

// def m_r_convert_to_ascii(messageText):
//     logger.debug("m_r_convert_to_ascii")
//     try:
//         # This will raise an exception if it is not pure ascii.
//         messageText.decode('ascii')
//         logger.debug("Text is pure ascii")
//     except Exception as e:
//         oldMessageText = messageText
//         # Try to convert unicode to ascii
//         # Make sure messageText is unicode before conversion
//         try:
//             messageText = unicode(messageText, "utf-8")
//         except TypeError:
//             logger.debug("messageText already unicdoe")

//         # Replace known unicode values which is not supported in unicodedata.normalize
//         for key, value in uni_to_ascii_dict.iteritems():
//             messageText = messageText.replace(key, value)

//         logger.debug("Normalizing and encoding to ascii")
//         # Do the conversion, this will make sure it passes.
//         logger.debug("%s", messageText)
//         messageText = unicodedata.normalize('NFKC', messageText).encode('ascii', 'ignore')
//         logger.debug("%s", messageText)
//         if oldMessageText == messageText:
//             logger.error("The message text is not pure ascii: %s", str(e))
//             raise ValueError("The message text is not pure ascii: %s", str(e))
//     logger.debug("Some chars have been replaced.")

//     return messageText;

// # PURPOSE:
// #  Log all of the following transactions:
// #  1) Login
// #  2) User Edits
// def m_r_log_transaction(user, req_type, req_user, req_desc, res_code, res_desc):
//     logger.debug("m_r_log_transaction")
//     db = m_r_db_connect()
//     cursor = db.cursor()

//     try:
//         query = """INSERT INTO nfe_wasp_config_transactions
//         (user, request_type, request_user, request_desc, result_code, result_desc)
//         VALUES (\'%s\',\'%s\',\'%s\',\'%s\',%s,\'%s\');""" % (user, req_type, req_user, req_desc, res_code, res_desc)
//         result = cursor.execute(query)
//         db.commit()
//     except Exception as e:
//         logger.error(e)
//         return -1;
//     return 0

// #Push the query_params to all the nodes. Retuns a list of comma seperated responses.
// def m_r_push_to_nodes(nodes,query_params,query_data=None):
//     logger.debug ('m_r_push_to_nodes')

//     final_response_dict = dict()#m_r_new_generic_response_json (code=-99,desc="",detail="")
//     final_response_dict['code'] = -1
//     final_response_dict['desc'] = "Invalid Node selected."
//     final_response_dict['detail'] = ""

//     try:
//         for i,ip in enumerate(NGF_TCPS_IPS):

//             if NGF_TCPS_NODE_NAMES[i] == nodes or nodes == 'all':
//                 port = NGF_TCPS_PORTS[i]
//                 url = ("http://%s:%s" + query_params) % (ip,port)
//                 logger.debug ("%s",url)

//                 if query_data==None:
//                     response = urllib2.urlopen(url).read()
//                 else:
//                     response = urllib2.urlopen(url,query_data).read()

//                 logger.debug (response)
//                 response_dict = json.loads(response)

//                 detail = ""
//                 try:
//                     detail = response_dict['detail']
//                 except Exception as e:
//                     logger.debug ("detail not defined in response.")

//                 #If an error occured, add details to the final_response_dict
//                 if response_dict['code'] % 100 != 0:
//                     if final_response_dict["code"] == -1:
//                         final_response_dict["code"] = response_dict["code"]
//                         final_response_dict["desc"] = NGF_TCPS_NODE_NAMES[i] + ': ' + response_dict["desc"]
//                         final_response_dict["detail"] = NGF_TCPS_NODE_NAMES[i] + ': ' + detail
//                     #if first error
//                     else:
//                         if final_response_dict['code'] % 100 == 0:
//                             final_response_dict['code'] = response_dict['code']
//                         final_response_dict['desc'] += ', ' + NGF_TCPS_NODE_NAMES[i] + ': ' + response_dict['desc']
//                         final_response_dict['detail'] += ', ' + NGF_TCPS_NODE_NAMES[i] + ': ' + detail
//                     #if not first error
//                 #if error occured on one of the nodes
//                 elif i == len(NGF_TCPS_IPS) -1 or nodes != 'all':
//                     final_response_dict['code'] = response_dict['code']
//                     final_response_dict['desc'] = response_dict['desc']
//                     final_response_dict['detail'] = detail
//                 #end if final iteration and all was successful, copy the success message.
//             #if for this node, or all nodes.
//     except Exception as e:
//         logger.error(e)
//         final_response_dict["code"] = -1
//         final_response_dict["desc"] = "An internal error occured"

//     return final_response_dict
