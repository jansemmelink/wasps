package wasps

import (
	"fmt"
	"strings"
	"time"

	"github.com/go-msvc/errors"
)

type Wasp struct {
	ID                    string     `json:"id" doc:"Unique ID in the database"`
	Name                  string     `json:"name" doc:"Unique name by which the WASP is identified"`
	OrganisationID        string     `json:"organisation_id" doc:"Refers to organisation that WASP belongs to"`
	Addr                  string     `json:"addr"`
	Locked                YesNo      `json:"locked" doc:"Flag set when WASP account is locked/suspended - blocking any access for this WASP."`
	PreventSBL            YesNo      `json:"prevent_sbl" doc:"Flag used to prevent WASP from being blacklisted"`
	FromAnyAddr           YesNo      `json:"from_any_address" doc:"Flag used to allow sending from any address"`
	ChargeOnSubmit        YesNo      `json:"charge_on_submit" doc:"Flag used in smsc_out to charge on submit (regardless of scheduled time), but delivery will be done only when scheduled."`
	ChargeMSISDN          string     `json:"charge_msisdn" doc:"If set, this address will be used for charging and not the original sender MSISDN. Has to be longer than 3 characters to take affect. If MT Charging is enabled, it will override this."`
	AllowOutTodSubmission YesNo      `json:"allow_out_tod_submission" doc:"Flag used to determine if WASP may submit out of TOD times. If set 'yes' submissions will be scheduled for the correct submission times."`
	TodStart              time.Time  `json:"tod_start" doc:"Time of day before which WASP is not allowed to submit messages. Format HH:MM:SS e.g. 06:00:00 When not specified, 00:00:00 is assumed."`
	TodEnd                time.Time  `json:"tod_end" doc:"Time of day after which WASP is not allowed to submit messages. Format HH:MM:SS e.g. 22:00:00. When not specified, 23:59:59 is assumed."`
	Expiry                time.Time  `json:"expiry" doc:"Date (and time) which this account will expire. It should be in the future when the WASP is created. When not specified, the WASP will never expire. After expiry, no further submissions will be accepted."`
	ActiveIP              IPAddr     `json:"active_ip" doc:"Active server IP Address for active-standby mode. This needs to be one of the configured servers."`
	ActivePort            int        `json:"active_port" doc:"Active server TCP Port number for active-standby mode. This needs to be one of the configured servers."`
	Send                  []Send     `json:"send" doc:"List of organisation addresses that WASP may send from"`
	Recv                  []Recv     `json:"recv" doc:"List of organisation addresses delivered to the WASP"`
	Server                []Server   `json:"server" doc:"List of servers to connect to (local/remote)"`
	Throttle              []Throttle `json:"throttle" doc:"List of throttles applied to this WASP as a whole"`
	Category              []Category `json:"category" doc:"List of categories applied to this WASP as a whole. Order is significant. The first match from this list is used."`
	Quota                 []Quota    `json:"quota" doc:"Quota for this WASP. When not specified, a default quota will be created that expires in 30 days with unlimited messages. One quota may have no id, being the default quota used when no others apply. All others must have a unique id. The default quota is deducted when no others apply."`
}

func (w Wasp) Validate() error {
	return nil
}

type YesNo bool

func (yn *YesNo) UnmarshalText(s string) error {
	switch strings.ToLower(s) {
	case "y", "yes", "1", "true":
		*yn = true
	case "n", "no", "0", "false":
		*yn = false
	default:
		return errors.Errorf("invalid value \"%s\" must be yes|no", s)
	}
	return nil
}

func (yn YesNo) String() string {
	if yn {
		return "yes"
	}
	return "no"
}

type IPAddr []int

func (ip *IPAddr) UnmarshalText(s string) error {
	n := make([]int, 4)
	if count, err := fmt.Scanf("%d.%d.%d.%d", &n[0], &n[1], &n[2], &n[3]); err != nil || count != 4 {
		return errors.Wrapf(err, "invalid IP \"%s\" expected a.b.c.d", s)
	}
	*ip = n
	return nil
}

func (ip IPAddr) String() string {
	if len(ip) != 4 {
		return "0.0.0.0"
	}
	return fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
}

type Send struct {
	Addr string `json:"addr" doc:"Address that WASP is allowed to send from"`
}

type Recv struct {
	Addr string `json:"addr" doc:"Address that WASP is allowed to recv on"`
}

//Description of a server that connections can be made to
type Server struct {
	// /*
	//  * reference to wasp owning this server element
	//  */
	// DATA_DESC_INTERNAL (const void* wasp_config_p);

	IP IPAddr `json:"ip" doc:"IP Address"`
	/*
	 * this flag is set to 1 in m_r_validate_wasp() when the IP address is blank or 0.0.0.0
	 * else it is 0
	 */
	// DATA_DESC_INTERNAL (int     any_ip_d);

	/*
	 * This flag is used to indicate if the server is part of an active-standby setup
	 * representing a standby server port.
	 */
	// DATA_DESC_INTERNAL (int     is_standby_d);

	Port          int                     `json:"port" doc:"TCP Port number"`
	Local         YesNo                   `json:"local" doc:"Local/remote flag. Yes for local. No for remote."`
	MaxNrConns    int                     `json:"max_nr_conns" doc:"Max total number of connections to this server (1..500)."`
	Balance       int                     `json:"balance" doc:"Load balance value for outgoing requests"`
	MaxMsgSize    int                     `json:"max_msg_size" doc:"Max size of messages determines size of message buffer. Changing this at runtime will close all client connections"`
	ConnTimeout   int                     `json:"conn_timeout" doc:"Max nr of seconds between messages before the connection is considered to be stale. If not received or sent any message in this nr of seconds, the connection is dropped. When this is 0, the timeout is never applied and stale connections are maintained until dropped by the client."`
	User          WaspConfigUser          `json:"user" doc:"Authentication settings required by the server"`
	ConnFrom      []WaspConfigConnectFrom `json:"conn_from" doc:"List of connection sources"`
	Protocol      WaspConfigProtocol      `json:"protocol" doc:"Protocol settings"`
	SSL           YesNo                   `json:"ssl" doc:"If set to 'yes' SSL-server side will be setup. Set certificate location in tcps.xml"`
	SSLReqCliCert YesNo                   `json:"ssl_req_cli_cert" doc:"If set to 'yes' SSL-server will enforce SSL_VERIFY_FAIL_IF_NO_PEER_CERT."`
	SvcDefName    string                  `json:"svc_def_name" doc:"(optional) Name of service to be triggered in the format <process name>.<fsm name> for example ngf_nav.nav_fsm"`
	NavItemID     string                  `json:"nav_item_id" doc:"(optional) Name of NAV item to be triggered. This should ONLY be set if the configured svc_def_name name is ngf_nav.nav_fsm !"`
}

type WaspConfigProtocol struct {
	Name   string            `json:"name"`
	Params map[string]string `json:"params"`
}

//Describes where server connections may originate from
type WaspConfigConnectFrom struct {
	IP         IPAddr `json:"IP Address"`
	MaxNrConns int    `json:"max_nr_conns" doc:"Max nr of connections from this source (1..500)."`
}

//Description of a WASP user
type WaspConfigUser struct {
	Type string `json:"type" doc:"User type (blank to accept any value)"`
	Name string `json:"name" doc:"User name (blank to accept any value)"`
	Pass string `json:"pass" doc:"User password (blank to accept any value"`
}

type Throttle struct {
	Period int `json:"period" doc:"Duration of this period in seconds. Defaults to 1 second when not specified. Valid Range is 1..86400 (i.e. one second to one day) and must be integer division of one day. Valid examples are 1, 10, 60 (1 minute), 300 (5 minutes), 3600 (1 hour), 43200 (12 hours), and 86400 (1 day). Periods starts at integer interval of duration after midnight."`
	Limit  int `json:"limit" doc:"Maximum number of messages in this period. Must be specified > 0."`
}

//Message category determined from keywords present in the content, to limit traffic to subscribers for some categories.
type Category struct {
	Name     string   `json:"name" doc:"Name to identify the category. This is not a keyword and has no meaning except that it is used for logging/reporting. It must be unique from other category names in this WASP. Example: \"weather\""`
	Keywords []string `json:"keywords" doc:"Any of these keywords found in a message, and the category limit is applied. Keywords may not be longer than 20 chars each, and total no more than 10 keywords in this field. All keywords must be written in lowercase and will match uppercase/lowercase words in a messages. If this is only defined as uppercase \"ANY\" this category applies to all messages not yet matched by previous categories and must be the last category in the list. Example: \"weather,cold,warm,dry,clouds,rain\""`
	Limit    int      `json:"limit" doc:"Maximum nr of messages in this category that may be sent to each subscriber every day. The limit should be 0..200 or -1 for unlimited. The rotation period defaults to one day in smsc.xml. You can change it to rotate faster, but it is a global setting for the whole SMSC."`
}

//Quota of messages that a organisation or WASP is allowed to submit before a given expiry time
type Quota struct {
	ID     string     `json:"id" doc:"Quota ID"`
	Nr     int        `json:"nr" doc:"Number of messages allowed to submit. -1 for unlimited submission."`
	Start  *time.Time `json:"start,omitempty" doc:"(optional)Date and time after which the quota may be used. If not specified, the quota can be used immediately."`
	Expiry *time.Time `json:"expiry,omitempty" doc:"Date and time when the quota will expire. If not specified, the quota never expires."`
}

// <?xml version="1.0"?>
// <wasp
//     id="config"
//     organisation_id="Config"
//     addr=""
//     locked="no"
//     prevent_sbl="no"
//     charge_on_submit="no"
//     tod_start="00:00:00"
//     tod_end="23:59:59"
//     expiry="00:00:00"
//     active_ip="0.0.0.0"
//     active_port="0">
//   <quota
//       nr="-1"
//       start="00:00:00"
//       expiry="00:00:00"/>
//   <server
//       ip="0.0.0.0"
//       port="19300"
//       local="yes"
//       max_nr_conns="10"
//       balance="0"
//       max_msg_size="20000"
//       conn_timeout="0">
//     <protocol name="HTTP"></protocol>
//     <user
//         type=""
//         name=""
//         pass=""/>
//   </server>
// </wasp>
