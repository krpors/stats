package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/crazy2be/ini"
	"io/ioutil"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"os/exec"
	"os/user"
	"path"
	"regexp"
	"sort"
	"strings"
	"text/template"
	"time"
)

// Constants for reading the settings file.
const (
	SETTING_USERNAME     string = "UserName"
	SETTING_PASSWORD     string = "Password"
	SETTING_FROM_ADDR    string = "FromAddress"
	SETTING_TO_ADDR      string = "ToAddress"
	SETTING_MAIL_FROM    string = "MailFrom"
	SETTING_MAIL_TO      string = "MailTo"
	SETTING_MAIL_HOST    string = "MailHost"
	SETTING_MAIL_SUBJECT string = "MailSubject"
)

// Struct with mail settings.
type MailSettings struct {
	Username    string
	Password    string
	MailFrom    string
	MailTo      string
	MailHost    string
	MailSubject string
	FromAddress string
	ToAddress   string
	Body        string
}

// Tries to fetches the auth host based on the MailHost, which should
// be in the format of `smtp.example.org:587'. The part before the port is
// used as the auth host.
func (ms *MailSettings) AuthHost() string {
	splitup := strings.Split(ms.MailHost, ":")
	if len(splitup) == 2 {
		return splitup[0]
	}

	return ms.MailHost
}

// Converts this struct to a string (debugging derp!)
func (ms *MailSettings) String() string {
	m := "Username=" + ms.Username + "\n"
	m += "Password=<HIDDEN>\n"
	m += "MailFrom=" + ms.MailFrom + "\n"
	m += "MailTo=" + ms.MailTo + "\n"
	m += "MailHost=" + ms.MailHost + "\n"
	m += "MailSubject=" + ms.MailSubject + "\n"
	m += "FromAddress=" + ms.FromAddress + "\n"
	m += "ToAddress=" + ms.ToAddress + "\n"
	m += fmt.Sprintf("Body length=%d", len(ms.Body))

	return m
}

// FsEntry contains information about the mounted file systems.
type FsEntry struct {
	FileSystem    string
	Size          string
	Used          string
	Avail         string
	UsePercentage string
	MountPoint    string
}

// String rep.
func (fs *FsEntry) String() string {
	return fmt.Sprintf(
		"%s, %s, %s, %s, %s, %s",
		fs.FileSystem,
		fs.Size,
		fs.Used,
		fs.Avail,
		fs.UsePercentage,
		fs.MountPoint)
}

// Gets the free disk space by doing a query using the `df' utility. Not
// pure Go-ish, but still. Works wonders for the moment. Returns nil list
// and a non-nil error when an error occurs (typically when the df command
// could not be invoked). 
func GetFreeDiskSpace() ([]FsEntry, error) {
	out, err := exec.Command("df", "--si").Output()
	if err != nil {
		return nil, err
	}

	mpEntries := make([]FsEntry, 0)
	lines := strings.Split(string(out), "\n")
	// skip the first line, it's the header anyway.
	for _, line := range lines[1:] {
		fld := strings.Fields(line)
		// we have 6 fields, so only continue then.
		if len(fld) == 6 {
			if fld[0] == "none" {
				continue
			}

			fs := FsEntry{}
			fs.FileSystem = fld[0]
			fs.Size = fld[1]
			fs.Used = fld[2]
			fs.Avail = fld[3]
			fs.UsePercentage = fld[4]
			fs.MountPoint = fld[5]

			mpEntries = append(mpEntries, fs)
		}
	}

	return mpEntries, nil
}

// Gets the external WAN address of the gateway of this box. Interesting
// to see whether the IP changed all of a sudden.
func GetExtIPAddress() (string, error) {
	type JsonIP struct {
		Ip    string `json:"ip"`
		About string `json:"about"`
	}

	resp, err := http.Get("http://jsonip.com")
	// defer closing of the body
	defer resp.Body.Close()
	if err != nil {
		return "", err
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	jip := JsonIP{}
	err = json.Unmarshal(body, &jip)
	if err != nil {
		return "", err
	}

	return jip.Ip, nil
}

// Gets the uptime of this box.
func GetUptime() (time.Duration, error) {
	ufile, err := ioutil.ReadFile("/proc/uptime")
	if err != nil {
		return 0, errors.New("Unable to read /proc/uptime")
	}

	uptimestr := strings.Split(string(ufile), " ")

	return time.ParseDuration(uptimestr[0] + "s")
}

// Formats the given duration as more readable string.
func FormatDuration(dur *time.Duration) string {
	var days int = int(dur.Hours() / 24)
	var hrs int = int(dur.Hours()) % 24
	var mins int = int(dur.Minutes()) % 60
	var secs int = int(dur.Seconds()) % 60

	return fmt.Sprintf("%d days, %d hours, %d minutes and %d seconds", days, hrs, mins, secs)
}

// Representation of an authentication failure.
type AuthFailure struct {
	// The ip address (IPv6 or IPv4) that failed
	IPAddress string
	// Amount of attempted logins
	Failures int
}

// Returns a simple string representation of this struct.
func (a AuthFailure) String() string {
	return fmt.Sprintf("%s (%d)", a.IPAddress, a.Failures)
}

// A list type definition for AuthFailure. Used to implement the sort.Interface to enable
// the sorting of this list via sort.Sort().
type AuthFailures []AuthFailure

// Returns the length of this slice/list by returning len(self)
func (a AuthFailures) Len() int {
	return len(a)
}

// Swaps elements.
func (a AuthFailures) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}

// Returns whether an IP address is 'less' than the other ip address
func (a AuthFailures) Less(i, j int) bool {
	return a[i].Failures > a[j].Failures
}

// This function analyzes the /var/log/auth.log for failed login attempts. It will
// return a map[string]int, where the key is a string which is an IP address, and the
// value of this key is the total amount of failed logins. When an error occurs, the
// returned map will be nil. When a-okay, the map will be non-nil, but the error will be.
func AnalyzeAuthLog() ([]AuthFailure, error) {
	infile := "/var/log/auth.log"
	authlog, err := ioutil.ReadFile(infile)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Unable to read `%s': %s", infile, err))
	}

	lines := strings.Split(string(authlog), "\n")

	rex, err := regexp.Compile(".*Failed password for (.*) from (.*) port.*")
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Failed to compile regular expression: %s", err))
	}

	// map with ip addresses, and amount of failed logins
	ipMap := make(map[string]int)

	_ = rex
	for _, line := range lines {
		if rex.MatchString(line) {
			var what []string = rex.FindStringSubmatch(line)
			ipAddress := what[2]
			// if IP is in the map, add 1 failed login attempt
			if ipMap[ipAddress] > 0 {
				ipMap[ipAddress] += 1
			} else {
				// if not in the map, set failed login attempt to 1
				ipMap[ipAddress] = 1
			}
		}
	}

	// iterate of the map in the end, add them to a list so we
	// can actually sort them.
	listfails := make(AuthFailures, 0)
	for k, v := range ipMap {
		listfails = append(listfails, AuthFailure{k, v})
	}

	sort.Sort(listfails)
	return listfails, nil
}

// Fetches the network interfaces, returns them as a string.
func GetInterfaces() ([]string, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return make([]string, 0), err
	}

	addrlist := make([]string, len(ifs))

	for index, iface := range ifs {
		addresses, _ := iface.Addrs()
		var s string = ""
		for addrindex, addr := range addresses {
			s += addr.String()
			if addrindex < len(addresses)-1 {
				s += ", "
			}
			addrlist[index] = s
		}
	}

	return addrlist, nil
}

// Actually sends the mail using the mail settings struct.
func SendMail(ms *MailSettings) {
	message := fmt.Sprintf("From: %s\n", ms.MailFrom)
	message += fmt.Sprintf("To: %s\n", ms.MailTo)
	message += fmt.Sprintf("Subject: %s\n", ms.MailSubject)
	message += "Content-Type: text/html; charset=UTF-8\n"
	message += "\n"
	message += ms.Body

	fmt.Println(ms)

	auth := smtp.PlainAuth("", ms.Username, ms.Password, ms.AuthHost())
	err := smtp.SendMail(ms.MailHost,
		auth,
		ms.FromAddress,
		[]string{ms.ToAddress},
		[]byte(message))
	if err != nil {
		fmt.Println("Error while sending mail:", err)
	}
}

func PrepareMail() string {
	ttext := `<html>
<body>
    <h2>Uptime: </h2>
    {{ .Uptime }}

    <h2>External IP address (WAN):</h2>
    {{ .ExtIp }}

    <h2>Network interfaces:</h2>
    <ul>
        {{ range .Interfaces }}
        <li>{{ . }}</li>
        {{ end }}
    </ul>

    <h2>Failed logins:</h2>
    <table style="width: 350px">
    <tr>
        <th style="text-align: left">IP address</th>
        <th style="text-align: left"># of failures</th>
    </tr>
    {{ range .Failures }}
    <tr>
        <td>{{ .IPAddress }}</td>
        <td>{{ .Failures }}</td>
    </tr>
    {{ end }}
    </table>

    <h3>Disk usage</h3>
    <table style="width: 100%">
        <thead>
            <tr>
                <th style="text-align: left">Filesystem</th>
                <th style="text-align: left">Size</th>
                <th style="text-align: left">Used</th>
                <th style="text-align: left">Available</th>
                <th style="text-align: left">Percentage used</th>
                <th style="text-align: left">Mount point</th>
            </tr>
        </thead>
        <tbody>
            {{ range .FreeSpace }}
            <tr>
                <td>{{ .FileSystem }}</td>
                <td>{{ .Size }}</td>
                <td>{{ .Used }}</td>
                <td>{{ .Avail }}</td>
                <td>{{ .UsePercentage }}</td>
                <td>{{ .MountPoint }}</td>
            </tr>
            {{ end }}
        </tbody>
    </table>
</body>
</html>`
	tmpl, err := template.New("test").Parse(ttext)
	if err != nil {
		panic(err)
	}

	type TemplData struct {
		Uptime     string
		ExtIp      string
		Interfaces []string
		Failures   []AuthFailure
		FreeSpace  []FsEntry
	}

	ut, _ := GetUptime()
	uptime := FormatDuration(&ut)
	extIp, _ := GetExtIPAddress()
	netwInterfaces, _ := GetInterfaces()
	failures, _ := AnalyzeAuthLog()
	fsEntry, _ := GetFreeDiskSpace()

	data := TemplData{uptime, extIp, netwInterfaces, failures, fsEntry}
	bytebuf := bytes.Buffer{}

	err = tmpl.Execute(&bytebuf, data)
	if err != nil {
		bytebuf.Reset()
		bytebuf.WriteString("Error in template execution")
	}

	return bytebuf.String()
}

// Prepares configuration by reading the config file from the current user's
// home directory. If the ~/.stats file does not exist, create it, and write 
// the default configuration keys. The file is automatically chmodded to 0600,
// to prevent world readable permissions (it stores a plaintext password).
func ReadConfiguration() (map[string]string, error) {
	// get the current user, so we can get the home dir.
	u, err := user.Current()
	if err != nil {
		return nil, errors.New("Cannot fetch current user")
	}

	var configFilePath string = path.Join(u.HomeDir, ".config", "stats")
	var configFile string = path.Join(configFilePath, "config")
	var settings map[string]string = make(map[string]string)

	file, err := os.Open(configFile)
	if err != nil {
		// If it doesn't exist, or the like, create it. First, create the directories
		// required, if necessary.
		if os.MkdirAll(configFilePath, 0700) != nil {
			return nil, errors.New(fmt.Sprintf("Failed to create configuration directory `%s'", configFilePath))
		}
		fmt.Printf("Creating default configuration file `%s'\n", configFile)
		file, err = os.Create(configFile)
		if err != nil {
			// We need a config file, so Exit(1) when it failed.
			return nil, errors.New(fmt.Sprintf("Failed to create configuration file `%s'\n", configFile))
		}
		// change permissions to be r/w to current user only. This file is
		// storing a plain text password, so we must not make it world readable.
		if err = file.Chmod(0600); err != nil {
			return nil, errors.New(fmt.Sprintf("Failed to change permissions on configuration file `%s'\n", configFile))
		}

		defer file.Close()

		// write some default settings:
		settings[SETTING_USERNAME] = "username"
		settings[SETTING_PASSWORD] = "password"
		settings[SETTING_MAIL_FROM] = "Server report <blah@example.com>"
		settings[SETTING_MAIL_TO] = "Name <email@example.com>"
		settings[SETTING_MAIL_HOST] = "smtp.gmail.com:587"
		settings[SETTING_MAIL_SUBJECT] = "Server report"
		settings[SETTING_FROM_ADDR] = "email@example.com"
		settings[SETTING_TO_ADDR] = "email@example.com"

		if err = ini.Save(configFile, settings); err != nil {
			return nil, errors.New(fmt.Sprintf("Unable to write to configuration file."))
		}
	}

	// If the file does exist though, read the properties:
	return ini.Load(configFile)
}

// Entry point.
func main() {
	settings, err := ReadConfiguration()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	mailinst := MailSettings{}
	mailinst.Username = settings[SETTING_USERNAME]
	mailinst.Password = settings[SETTING_PASSWORD]
	mailinst.MailHost = settings[SETTING_MAIL_HOST]
	mailinst.MailFrom = settings[SETTING_MAIL_FROM]
	mailinst.MailTo = settings[SETTING_MAIL_TO]
	mailinst.MailSubject = settings[SETTING_MAIL_SUBJECT]
	mailinst.FromAddress = settings[SETTING_FROM_ADDR]
	mailinst.ToAddress = settings[SETTING_TO_ADDR]
	mailinst.Body = PrepareMail()

	SendMail(&mailinst)
}
