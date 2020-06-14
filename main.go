package main

//Dependent on MySQL and bgpq3 being installed locally

import (
	"bufio"
	"bytes"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/ssh"
)

type peeringdborg struct {
	Data []struct {
		Aka                      string  `json:"aka"`
		Asn                      float64 `json:"asn"`
		Created                  string  `json:"created"`
		ID                       float64 `json:"id"`
		InfoIpv6                 bool    `json:"info_ipv6"`
		InfoMulticast            bool    `json:"info_multicast"`
		InfoNeverViaRouteServers bool    `json:"info_never_via_route_servers"`
		InfoPrefixes4            float64 `json:"info_prefixes4"`
		InfoPrefixes6            float64 `json:"info_prefixes6"`
		InfoRatio                string  `json:"info_ratio"`
		InfoScope                string  `json:"info_scope"`
		InfoTraffic              string  `json:"info_traffic"`
		InfoType                 string  `json:"info_type"`
		InfoUnicast              bool    `json:"info_unicast"`
		IrrAsSet                 string  `json:"irr_as_set"`
		LookingGlass             string  `json:"looking_glass"`
		Name                     string  `json:"name"`
		NetfacSet                []struct {
			City     string  `json:"city"`
			Country  string  `json:"country"`
			Created  string  `json:"created"`
			FacID    float64 `json:"fac_id"`
			ID       float64 `json:"id"`
			LocalAsn float64 `json:"local_asn"`
			Name     string  `json:"name"`
			Status   string  `json:"status"`
			Updated  string  `json:"updated"`
		} `json:"netfac_set"`
		NetixlanSet []struct {
			Asn         float64 `json:"asn"`
			Created     string  `json:"created"`
			ID          float64 `json:"id"`
			Ipaddr4     string  `json:"ipaddr4"`
			Ipaddr6     string  `json:"ipaddr6"`
			IsRsPeer    bool    `json:"is_rs_peer"`
			IxID        float64 `json:"ix_id"`
			IxlanID     float64 `json:"ixlan_id"`
			Name        string  `json:"name"`
			Notes       string  `json:"notes"`
			Operational bool    `json:"operational"`
			Speed       float64 `json:"speed"`
			Status      string  `json:"status"`
			Updated     string  `json:"updated"`
		} `json:"netixlan_set"`
		Notes string `json:"notes"`
		Org   struct {
			Address1 string        `json:"address1"`
			Address2 string        `json:"address2"`
			City     string        `json:"city"`
			Country  string        `json:"country"`
			Created  string        `json:"created"`
			FacSet   []interface{} `json:"fac_set"`
			ID       float64       `json:"id"`
			IxSet    []interface{} `json:"ix_set"`
			Name     string        `json:"name"`
			NetSet   []float64     `json:"net_set"`
			Notes    string        `json:"notes"`
			State    string        `json:"state"`
			Status   string        `json:"status"`
			Updated  string        `json:"updated"`
			Website  string        `json:"website"`
			Zipcode  string        `json:"zipcode"`
		} `json:"org"`
		OrgID           float64       `json:"org_id"`
		PocSet          []interface{} `json:"poc_set"`
		PolicyContracts string        `json:"policy_contracts"`
		PolicyGeneral   string        `json:"policy_general"`
		PolicyLocations string        `json:"policy_locations"`
		PolicyRatio     bool          `json:"policy_ratio"`
		PolicyURL       string        `json:"policy_url"`
		RouteServer     string        `json:"route_server"`
		Status          string        `json:"status"`
		Updated         string        `json:"updated"`
		Website         string        `json:"website"`
	} `json:"data"`
	Meta struct{} `json:"meta"`
}

type peeringdbixinfo struct {
	Data []struct {
		Asn         float64 `json:"asn"`
		Created     string  `json:"created"`
		ID          float64 `json:"id"`
		Ipaddr4     string  `json:"ipaddr4"`
		Ipaddr6     string  `json:"ipaddr6"`
		IsRsPeer    bool    `json:"is_rs_peer"`
		IxID        float64 `json:"ix_id"`
		IxlanID     float64 `json:"ixlan_id"`
		Name        string  `json:"name"`
		NetID       float64 `json:"net_id"`
		Notes       string  `json:"notes"`
		Operational bool    `json:"operational"`
		Speed       float64 `json:"speed"`
		Status      string  `json:"status"`
		Updated     string  `json:"updated"`
	} `json:"data"`
	Meta struct{} `json:"meta"`
}

type peer struct {
	asn   string
	asset string
}

type routerUpdateInfo struct {
	asn    string
	prefix string
}

var modePtr = flag.String("mode", "update", "(update) prefix list, (add) peer, (remove) a peer, or (clean)up after a bad run.")
var asnPtr = flag.String("asn", "", "[Add/remove mode] Specify the ASN to be added/removed")
var md5Ptr = flag.String("md5", "", "[Add mode, optional] If a MD5 password is needed for a session, set it manually")
var peernamePtr = flag.String("peername", "", "[Add mode, optional] Set peer name")
var maxv4Ptr = flag.String("maxv4", "", "[Add mode, optional] Set max prefixes v4")
var maxv6Ptr = flag.String("maxv6", "", "[Add mode, optional] Set max prefixes v6")
var assetPtr = flag.String("asset", "", "[Add mode, optional] Set the AS-SET")
var v4Ptr = flag.String("v4", "", "[Add mode, optional] Set the peer v4 address")
var v6Ptr = flag.String("v6", "", "[Add mode, optional] Set the peer v6 address")
var nodbPtr = flag.String("nodb", "0", "[Add mode, optional] Do not query PeeringDB for data")

//SQLUsername is the SQL username
var SQLUsername = "bgpdb"

//SQLPassword is the SQL password
var SQLPassword = "password"

//SQLDatabase is the SQL database
var SQLDatabase = "bgpdb"

//IXID from peeringDB. 2163 for FCIX
var IXID = "2163"

//Source for IRR data
var source = "rr.ntt.net"

//IPaddress AND PORT of the MikroTik router
var IPaddress = "192.0.2.1:22"

//Username of the MikroTik router
var username = "user"

//Password of the MikroTik router
var password = "password"

func establishSSH() *ssh.Client {
	sshConfig := &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.HostKeyCallback(func(hostname string, remote net.Addr, key ssh.PublicKey) error { return nil }),
	}
	sshConnection, err := ssh.Dial("tcp", IPaddress, sshConfig)
	if err != nil {
		log.Fatal(err)
	}
	return sshConnection
}

func runSSHCommand(sshConnection *ssh.Client, command string) {
	sshSession, err := sshConnection.NewSession()
	defer sshSession.Close()
	if err != nil {
		log.Fatal(err)
	}
	err = sshSession.Run(command)
	if err != nil {
		log.Fatal(err)
	}
}

func closeSSH(sshClient *ssh.Client) {
	sshClient.Close()
}

func compileSQLPassword() string {
	return SQLUsername + ":" + SQLPassword + "@/" + SQLDatabase
}

func establishDB() *sql.DB {
	db, err := sql.Open("mysql", compileSQLPassword()) //Open a database connection
	if err != nil {
		log.Fatal(err)
	}
	return db
}

func bgpq3query(query string, version string, prefixlist *[]string) {
	addon := "-4"
	if version == "6" {
		addon = "-6"
	}
	locsource := "-h" + source
	tacf := "-F%n/%l\n"
	cmd := exec.Command("bgpq3", locsource, query, addon, tacf)
	buffer := new(bytes.Buffer)
	cmd.Stdout = buffer //os.Stdout for debug
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		log.Fatal(err)
	}
	*prefixlist = strings.Split(buffer.String(), "\n")
}

func askQuestion(question string) string { //Ask the user a question, do some basic cleaning up, and return the value
	fmt.Print(question)
	reader := bufio.NewReader(os.Stdin)
	id, errread := reader.ReadString('\n')
	id = strings.TrimSpace(id)
	if errread != nil {
		log.Fatal(errread)
	}
	fmt.Println("")
	return id
}

func getData(url string) []byte { //Use a HTTP get to request JSON data
	httpClient := http.Client{
		Timeout: time.Second * 5,
	}
	request, errreq := http.NewRequest(http.MethodGet, url, nil)
	if errreq != nil {
		log.Fatal(errreq)
	}
	response, geterr := httpClient.Do(request)
	if geterr != nil {
		log.Fatal(geterr)
	}
	if response.Body != nil {
		defer response.Body.Close()
	}
	text, texterr := ioutil.ReadAll(response.Body)
	if texterr != nil {
		log.Fatal(texterr)
	}
	return text
}

func setDataBasedOnSource(ptrarg string, peeringdbarg string, question string) string { //Based on one of a few sources, return the value we consider right
	returnv := ""
	if ptrarg != "" { //Is there a pointer showing they already told us
		returnv = ptrarg
	} else if *nodbPtr == "0" { //Is peeringdb acceptable
		returnv = peeringdbarg
	} else { //Do we just need to ask
		returnv = askQuestion(question)
	}
	return returnv
}

func printPeerData(peername string, maxv4 string, maxv6 string, asset string, md5 string, v4 string, v6 string, v4count int, v6count int) {
	fmt.Println("-----Data to be used-----") //spacer
	fmt.Println("1) Peer name: " + peername)
	fmt.Println("2) Max v4: " + maxv4)
	fmt.Println("3) Max v6: " + maxv6)
	fmt.Println("4) AS-SET: " + asset)
	fmt.Println("5) MD5: " + md5)
	fmt.Println("6) v4: " + v4)
	fmt.Println("7) v6: " + v6)
	fmt.Println("!!!Remember to check the AS-SET manually for validity!!!")
	fmt.Println("This AS-SET contains:")
	fmt.Println(strconv.Itoa(v4count) + " IPv4 prefixes")
	fmt.Println(strconv.Itoa(v6count) + " IPv6 prefixes")
	fmt.Println("-----")
}

func sqlExecute(cmd string, db *sql.DB) {
	_, err := db.Exec(cmd)
	if err != nil {
		log.Fatal(err)
	}
}

func sqlInsertCheck(input string) string {
	if input == "" {
		return ",NULL"
	}
	return ",'" + input + "'"
}

func addASNToTable(asn string, peerv4 string, peerv6 string, asset string, maxv4 string, maxv6 string, md5 string, legalname string, db *sql.DB) {
	statement := "INSERT INTO asns (asn, peerv4, peerv6, asset, maxv4, maxv6, md5, legalname) VALUES "
	statement = statement + "('" + asn + "'" //have to start seperately to avoid a start comma
	statement = statement + sqlInsertCheck(peerv4) + sqlInsertCheck(peerv6) + sqlInsertCheck(asset) + sqlInsertCheck(maxv4)
	statement = statement + sqlInsertCheck(maxv6) + sqlInsertCheck(md5) + sqlInsertCheck(legalname) + ")"
	sqlExecute(statement, db)
}

func removeASNFromTable(asn string, db *sql.DB) {
	statement := "DELETE FROM asns WHERE asn = " + asn
	sqlExecute(statement, db)
}

func dropTable(name string, db *sql.DB) {
	sqlExecute("DROP TABLE "+name, db)
}

func emptyTable(name string, db *sql.DB) {
	sqlExecute("DELETE FROM "+name, db)
}

func createPrefixTable(name string, db *sql.DB) {
	sqlExecute("CREATE TABLE "+name+" (`prefix` varchar(50) CHARACTER SET utf16 NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf16", db)
}

func populatePrefixTable(prefixlistin *[]string, tablename string, db *sql.DB) {
	prefixlist := *prefixlistin
	chunksize := 100 //Used for dealing with massive prefix lists - send in massive chunks
	for count := 0; (len(prefixlist) - 2) > count; count = count + chunksize {
		pushblock := "('" + prefixlist[count] + "')"
		for innercount := count + 1; innercount < chunksize+count && innercount < (len(prefixlist)-2); innercount++ {
			pushblock = pushblock + ",('" + prefixlist[innercount] + "')"
		}
		sqlExecute("INSERT INTO "+tablename+" (prefix) VALUES "+pushblock, db)
	}
}

func copyNewPeerPrefixesToAddQueue(asn string, version string, db *sql.DB) {
	tablename := asn + "_v" + version
	sqlExecute("SET @theasn = "+asn, db)
	sqlExecute("INSERT INTO addv"+version+"(asn, prefix) SELECT @theasn,prefix FROM "+tablename, db)
}

func askForASN() string {
	asn := ""
	if *asnPtr == "" {
		asn = askQuestion("What is the peer's ASN (without the AS prefix)?: ")
	} else {
		asn = *asnPtr
	}
	return asn
}

func createAndPopulateTables(v4in *[]string, v6in *[]string, asn string, update int, db *sql.DB) {
	table4name := ""
	table6name := ""
	if update == 1 {
		table4name = asn + "_v4_UPDATE"
		table6name = asn + "_v6_UPDATE"
	} else {
		table4name = asn + "_v4"
		table6name = asn + "_v6"
	}
	v4prefixes := *v4in
	v6prefixes := *v6in
	createPrefixTable(table4name, db)
	createPrefixTable(table6name, db)
	populatePrefixTable(&v4prefixes, table4name, db)
	populatePrefixTable(&v6prefixes, table6name, db)
}

func emptyAllQueues(db *sql.DB) {
	emptyTable("addv4", db)
	emptyTable("addv6", db)
	emptyTable("deletev4", db)
	emptyTable("deletev6", db)
}

func printRSPL(name string, asn string, asset string) {
	fmt.Println("RSPL info for RIPE:------")
	fmt.Println("remarks: ")
	fmt.Println("remarks:         --==" + name + "==--")
	fmt.Println("import:          from AS" + asn + " accept AS " + asset)
	fmt.Println("export:          to AS" + asn + " announce AS-IGLOO22225")
	fmt.Println("mp-import:       afi ipv6.unicast from AS" + asn + " accept " + asset)
	fmt.Println("mp-export:       afi ipv6.unicast to AS" + asn + " announce AS-IGLOO22225")
	fmt.Println("END RSPL info for RIPE:------")
}

func addPeer() {
	asn := ""
	v4 := ""
	v6 := ""
	peername := ""
	asset := ""
	maxv4 := ""
	maxv6 := ""
	asn = askForASN()
	if *nodbPtr == "0" { //If we *havnt* disabled PeeringDB
		pop := peeringdbixinfo{}
		org := peeringdborg{}
		url := "https://www.peeringdb.com/api/netixlan?ix_id=" + IXID + "&asn=" + asn
		//fetch the url, unmarshall it
		text := getData(url)
		jsonerr := json.Unmarshal(text, &pop)
		if jsonerr != nil {
			log.Fatal(jsonerr)
		}
		url = "https://www.peeringdb.com/api/net/" + fmt.Sprintf("%.0f", pop.Data[0].NetID) //the NETID is the same within an ASN, so we can just take the first for our data gathering
		text = getData(url)
		sjsonerr := json.Unmarshal(text, &org)
		if sjsonerr != nil {
			log.Fatal(sjsonerr)
		}
		fmt.Println("Here is what was found in peeringdb: ")
		fmt.Println("Peer name: " + org.Data[0].Org.Name)
		fmt.Println("Max prefixes (v4): " + fmt.Sprintf("%.0f", org.Data[0].InfoPrefixes4))
		fmt.Println("Max prefixes (v6): " + fmt.Sprintf("%.0f", org.Data[0].InfoPrefixes6))
		fmt.Println("AS-SET: " + org.Data[0].IrrAsSet)
		flag := 0
		for count := 0; count < len(pop.Data); count++ {
			fmt.Println("IPv4(" + strconv.Itoa(count) + "): " + pop.Data[count].Ipaddr4)
			fmt.Println("IPv6(" + strconv.Itoa(count) + "): " + pop.Data[count].Ipaddr6)
			if count != 0 {
				flag = 1
			}
		}
		ipselection := 0
		if flag == 1 { //Deal with chosing which IP they want
			ipselection, _ = strconv.Atoi(askQuestion("What IP set would you like to peer with?: "))
		}
		v4 = pop.Data[ipselection].Ipaddr4
		v6 = pop.Data[ipselection].Ipaddr6
		peername = org.Data[0].Org.Name
		maxv4 = fmt.Sprintf("%.0f", org.Data[0].InfoPrefixes4)
		maxv6 = fmt.Sprintf("%.0f", org.Data[0].InfoPrefixes6)
		asset = org.Data[0].IrrAsSet
	}
	//Go through and pick a winner data source. If nothing is provided, ask. Flags > PeeringDB > in-line challenge
	peername = setDataBasedOnSource(*peernamePtr, peername, "Peer name?: ") //Use the pre-assigned peeringdb vars to avoid having to needlessly declare objects if peeringdb isnt being used
	maxv4 = setDataBasedOnSource(*maxv4Ptr, maxv4, "Max v4?: ")
	maxv6 = setDataBasedOnSource(*maxv6Ptr, maxv6, "Max v6?: ")
	asset = setDataBasedOnSource(*assetPtr, asset, "AS-SET?: ")
	//MD5 - uncommon enough where you just gotta manually set it if you want it used
	md5 := ""
	if *md5Ptr != "" {
		md5 = *md5Ptr
	}
	v4 = setDataBasedOnSource(*v4Ptr, v4, "v4?: ")
	v6 = setDataBasedOnSource(*v6Ptr, v6, "v6?: ")
	var v6prefixes []string //To avoid allocating and deallocating what could be a massive slice multiple times
	var v4prefixes []string
	bgpq3query(asset, "4", &v4prefixes) //Remember, number -1 since bgpq3's output will include one at the end
	bgpq3query(asset, "6", &v6prefixes)
	printPeerData(peername, maxv4, maxv6, asset, md5, v4, v6, (len(v4prefixes) - 2), (len(v6prefixes) - 2))
	confirmation := askQuestion("Type yes in all caps to confirm you are OK with this OR enter a number to edit: ")
	for {
		if confirmation == "YES" {
			break
		} else if confirmation == "1" {
			peername = askQuestion("Peer name?: ")
		} else if confirmation == "2" {
			maxv4 = askQuestion("Max v4?: ")
		} else if confirmation == "3" {
			maxv6 = askQuestion("Max v6?: ")
		} else if confirmation == "4" {
			asset = askQuestion("AS-SET?: ")
			v4prefixes = nil //If they changed the AS-SET, we need to recompute it
			v6prefixes = nil
			bgpq3query(asset, "4", &v4prefixes)
			bgpq3query(asset, "6", &v6prefixes)
		} else if confirmation == "5" {
			md5 = askQuestion("MD5?: ")
		} else if confirmation == "6" {
			v4 = askQuestion("v4?: ")
		} else if confirmation == "7" {
			v6 = askQuestion("v6?: ")
		}
		printPeerData(peername, maxv4, maxv6, asset, md5, v4, v6, len(v4prefixes)-2, len(v6prefixes)-2) //This point will only be reached if they didn't enter "YES"
		confirmation = askQuestion("Type yes in all caps to confirm you are OK with this OR enter a number to edit: ")
	}

	//Print RSPL which we can then copy+paste into the RIPE DB
	printRSPL(peername, asn, asset)

	db := establishDB()
	defer db.Close()
	fmt.Print("Adding peer to records...")
	//Add a peer to the list of who we peer with
	addASNToTable(asn, v4, v6, asset, maxv4, maxv6, md5, peername, db)

	//Create and populate tables
	createAndPopulateTables(&v4prefixes, &v6prefixes, asn, 0, db)
	fmt.Println("done.")
	fmt.Print("Copying records to the add queue...")
	//Push the prefixes into the add queue
	copyNewPeerPrefixesToAddQueue(asn, "4", db)
	copyNewPeerPrefixesToAddQueue(asn, "6", db)
	fmt.Println("done.")
	fmt.Print("Executing add queue...")
	executeTheAddAndDropQueue(db)
	fmt.Println("done.")
	//set up session
	sshClient := establishSSH()
	defer closeSSH(sshClient)
	fmt.Print("Adding base prefix list...")
	runSSHCommand(sshClient, "/routing filter add action=discard chain=\"IMPORT-"+asn+"\" match-chain=\"sanity-check\"")
	runSSHCommand(sshClient, "/routing filter add action=discard chain=\"IMPORT-"+asn+"\" match-chain=\"sanity-check-notransit\"")
	runSSHCommand(sshClient, "/routing filter add chain=\"IMPORT-"+asn+"\" set-bgp-local-pref=250 set-distance=15")
	runSSHCommand(sshClient, "/routing filter add action=accept chain=\"IMPORT-"+asn+"\" match-chain="+asn+"PREFIXES")
	runSSHCommand(sshClient, "/routing filter add action=discard chain=\"IMPORT-"+asn+"\"")
	fmt.Println("done.")
	fmt.Print("Turning up session and cleaning up...")
	if v4 != "" {
		if md5 == "" {
			runSSHCommand(sshClient, "/routing bgp peer add in-filter=\"IMPORT-"+asn+"\" instance=ix max-prefix-limit="+maxv4+" name="+asn+"v4 out-filter=\"EXPORT-global\" remote-address="+v4+" remote-as="+asn+" ttl=default")
		} else {
			runSSHCommand(sshClient, "/routing bgp peer add in-filter=\"IMPORT-"+asn+"\" instance=ix max-prefix-limit="+maxv4+" name="+asn+"v4 out-filter=\"EXPORT-global\" remote-address="+v4+" remote-as="+asn+" tcp-md5-key="+md5+" ttl=default")
		}
	}
	if v6 != "" {
		if md5 == "" {
			runSSHCommand(sshClient, "/routing bgp peer add address-families=ipv6 in-filter=\"IMPORT-"+asn+"\" instance=ix max-prefix-limit="+maxv6+" name="+asn+"v6 out-filter=\"EXPORT-global\" remote-address="+v6+" remote-as="+asn+" ttl=default")
		} else {
			runSSHCommand(sshClient, "/routing bgp peer add address-families=ipv6 in-filter=\"IMPORT-"+asn+"\" instance=ix max-prefix-limit="+maxv6+" name="+asn+"v6 out-filter=\"EXPORT-global\" remote-address="+v6+" remote-as="+asn+" tcp-md5-key="+md5+" ttl=default")
		}
	}
	emptyAllQueues(db)
	fmt.Println("done.")
}

func removePeer() {
	asn := ""
	asn = askForASN()
	//tear down session and filters
	sshClient := establishSSH()
	defer closeSSH(sshClient)
	fmt.Print("Removing peer and filters...")
	runSSHCommand(sshClient, "/routing bgp peer remove [/routing bgp peer find where name="+asn+"v4]")
	runSSHCommand(sshClient, "/routing bgp peer remove [/routing bgp peer find where name="+asn+"v6]")
	runSSHCommand(sshClient, "/routing filter remove [/routing filter find where chain="+asn+"PREFIXES]")
	runSSHCommand(sshClient, "/routing filter remove [/routing filter find where chain=\"IMPORT-"+asn+"\"]")
	fmt.Println("done.")
	fmt.Print("Cleaning DB...")
	db := establishDB()
	defer db.Close()
	removeASNFromTable(asn, db)
	dropTable(asn+"_v4", db)
	dropTable(asn+"_v6", db)
	fmt.Println("done.")
	fmt.Println("Peer removed. Don't forget to remove them from RSPL!")
}

func createUpdateTable(asn string, asset string, db *sql.DB) {
	var v6prefixes []string //To avoid allocating and deallocating what could be a massive slice multiple times
	var v4prefixes []string
	bgpq3query(asset, "4", &v4prefixes) //Remember, number -1 since bgpq3's output will include one at the end
	bgpq3query(asset, "6", &v6prefixes)
	createAndPopulateTables(&v4prefixes, &v6prefixes, asn, 1, db)

}
func clearUpdateTable(asn string, db *sql.DB) {
	table := asn + "_v4_UPDATE"
	dropTable(table, db)
	table = asn + "_v6_UPDATE"
	dropTable(table, db)
}

func queryForTableBeingFilled(asn string, v4orv6 string, db *sql.DB) bool {
	rows, err := db.Query("select prefix from " + asn + "_v" + v4orv6 + "_UPDATE LIMIT 1")
	if err != nil {
		log.Fatal(err)
	}
	filled := ""
	for rows.Next() {
		err = rows.Scan(&filled)
	}
	if err != nil {
		log.Fatal(err)
	}
	if filled == "" {
		return false
	}
	return true
}

func buildUpdatesFromDeltas(asn string, db *sql.DB) { //Let SQL do all the hard comparison work
	sqlExecute("SET @theasn = "+asn, db)
	v4filled := queryForTableBeingFilled(asn, "4", db) //Make sure we have prefixes to add so we don't just delete everything by accident
	v6filled := queryForTableBeingFilled(asn, "6", db)
	if v4filled == true {
		sqlExecute("INSERT INTO addv4 (asn,prefix) (SELECT @theasn, B.prefix FROM "+asn+"_v4 A RIGHT JOIN "+asn+"_v4_UPDATE B on A.prefix = B.prefix WHERE A.prefix IS NULL)", db)
		sqlExecute("INSERT INTO deletev4 (asn,prefix) (SELECT @theasn,A.prefix FROM "+asn+"_v4 A LEFT JOIN "+asn+"_v4_UPDATE B on A.prefix = B.prefix WHERE B.prefix IS NULL)", db)
	}
	if v6filled == true {
		sqlExecute("INSERT INTO addv6 (asn,prefix) (SELECT @theasn, B.prefix FROM "+asn+"_v6 A RIGHT JOIN "+asn+"_v6_UPDATE B on A.prefix = B.prefix WHERE A.prefix IS NULL)", db)
		sqlExecute("INSERT INTO deletev6 (asn,prefix) (SELECT @theasn,A.prefix FROM "+asn+"_v6 A LEFT JOIN "+asn+"_v6_UPDATE B on A.prefix = B.prefix WHERE B.prefix IS NULL)", db)
	}
}

func updateRecordedTable(asn string, db *sql.DB) {
	emptyTable(asn+"_v4", db)
	emptyTable(asn+"_v6", db)
	sqlExecute("INSERT INTO "+asn+"_v4 (prefix) (SELECT prefix FROM "+asn+"_v4_UPDATE)", db)
	sqlExecute("INSERT INTO "+asn+"_v6 (prefix) (SELECT prefix FROM "+asn+"_v6_UPDATE)", db)
}

func generateUpdateMessage(mode string, prefix string, asn string, version string) string {
	maxlength := "0"
	if version == "4" {
		maxlength = "24"
	} else if version == "6" {
		maxlength = "48"
	} else {
		log.Fatal("Message attempted to generate without 4 or 6 set!")
	}
	if mode != "add" && mode != "remove" {
		log.Fatal("Message attempted to generate without add or remove mode!")
	}
	if mode == "remove" { //Because the direct option isn't an option on mikrotik
		return "/routing filter remove [/routing filter find where prefix=\"" + prefix + "\" chain=\"" + asn + "PREFIXES\""
	}
	return "/routing filter add action=accept chain=" + asn + "PREFIXES prefix=" + prefix + " prefix-length=0-" + maxlength

}

func getRowCount(table string, db *sql.DB) int {
	rows, err := db.Query("select count(*) as count from " + table) //Get a count of records
	if err != nil {
		log.Fatal(err)
	}
	rowcount := 0
	for rows.Next() {
		err = rows.Scan(&rowcount)
	}
	if err != nil {
		log.Fatal(err)
	}
	return rowcount
}

func isItV4OrV6(counter int) string {
	if counter == 0 || counter == 2 {
		return "4"
	}
	return "6"
}

func getMode(count int) string {
	if count == 0 || count == 1 {
		return "add"
	} else if count == 2 || count == 3 {
		return "remove"
	}
	return "ERR"
}

func executeTheAddAndDropQueue(db *sql.DB) {
	tableNames := [4]string{"addv4", "addv6", "deletev4", "deletev6"}
	sshClient := establishSSH()
	prefixesperpush := 10
	sendtext := ""
	defer closeSSH(sshClient)
	for count := 0; count < 4; count++ {
		rowcount := getRowCount(tableNames[count], db)
		var deltavalues = make([]routerUpdateInfo, rowcount)
		rows, err := db.Query("select * from " + tableNames[count]) //Get the records
		if err != nil {
			log.Fatal(err)
		}
		for icount := 0; rows.Next(); icount++ {
			err = rows.Scan(&deltavalues[icount].asn, &deltavalues[icount].prefix) //Pull into the struct
		}
		for dcount := 0; dcount < rowcount; dcount++ {
			sendtext = sendtext + "; " + generateUpdateMessage(getMode(count), deltavalues[dcount].prefix, deltavalues[dcount].asn, isItV4OrV6(count))
			if dcount%prefixesperpush == 0 || dcount == rowcount-1 { // Every ROWCOUNT times OR at the end, push the prefixes into the router
				runSSHCommand(sshClient, sendtext)
				sendtext = ""
			}
		}
	}
	runSSHCommand(sshClient, "/routing bgp peer refresh-all") //Refresh all peers
}

func updatePeer() {
	//query the asn table, get list of peers and their as-sets
	db := establishDB()
	defer db.Close()

	rowcount := getRowCount("asns", db)
	var peers = make([]peer, rowcount)

	rows, err := db.Query("select asn, asset from asns") //Get a list of who we have and move from there
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close() //Close rows when we are done with updating
	fmt.Println("ASN list obtained, processing...")
	for count := 0; rows.Next(); count++ { //Get all of the necessary peer data from SQL
		err = rows.Scan(&peers[count].asn, &peers[count].asset)
	}
	if err != nil {
		log.Fatal(err)
	}

	for count := 0; count < rowcount; count++ {
		fmt.Print("Setting add/drop for AS" + peers[count].asn + "...")
		createUpdateTable(peers[count].asn, peers[count].asset, db) //Create and fill update tables
		buildUpdatesFromDeltas(peers[count].asn, db)                //do a join to discover the deltas and push to add/drop tables
		fmt.Println("done.")
	}

	executeTheAddAndDropQueue(db)

	for count := 0; count < rowcount; count++ {
		updateRecordedTable(peers[count].asn, db)
		clearUpdateTable(peers[count].asn, db) //clean up after ourselves
	}
	emptyAllQueues(db)

}

func cleanupUpdateTables() {
	db := establishDB()
	defer db.Close()

	rows, err := db.Query("show tables WHERE Tables_in_bgp LIKE '%_UPDATE'") //Get a list of surviving tables
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close() //Close rows when we are done with updating
	tablename := ""
	for rows.Next() { //Get all of the necessary peer data from SQL
		err = rows.Scan(&tablename)
		sqlExecute("DROP TABLE "+tablename, db)
	}
	if err != nil {
		log.Fatal(err)
	}
	emptyAllQueues(db)

}

func main() {
	//Confirm input mode
	flag.Parse()
	if *modePtr == "add" {
		addPeer()
	} else if *modePtr == "remove" {
		removePeer()
	} else if *modePtr == "update" {
		updatePeer()
	} else if *modePtr == "clean" {
		cleanupUpdateTables() //Clean up after a bad run
	} else {
		fmt.Println("Whatcha talking bout Willis?")
	}

}
