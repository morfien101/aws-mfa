package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/user"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/sts"
	"gopkg.in/ini.v1"
)

var (
	flagSrcProfile = flag.String("s", "default", "Source (primary) profile")
	flagDstProfile = flag.String("d", "", "MFA-enabled profile")
	flagCode       = flag.String("c", "", "MFA code. Will need at least few seconds of validity left on the token.")
	flagTimeLeft   = flag.Bool("t", false, "Show time left on token")
	flagQuite      = flag.Bool("q", false, "Quite mode")

	version = "dev"
)

func checkFatalError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func logIt(msg string) {
	if !*flagQuite {
		log.Println(msg)
	}
}

func main() {
	flag.Parse()

	if *flagTimeLeft {
		if *flagSrcProfile == "" {
			flag.Usage()
			os.Exit(1)
		}
		err := checkValidityTime(*flagSrcProfile)
		checkFatalError(err)
		os.Exit(0)
	}

	if *flagSrcProfile == "" || *flagDstProfile == "" || *flagCode == "" {
		flag.Usage()
		os.Exit(1)
	}

	conf := &aws.Config{
		Credentials: credentials.NewSharedCredentials("", *flagSrcProfile),
	}

	sess, err := session.NewSession(conf)
	checkFatalError(err)

	creds, err := collectStsCreds(sess, *flagCode)
	checkFatalError(err)

	err = writeCredentials(creds, *flagSrcProfile, *flagDstProfile)
	checkFatalError(err)

	logIt(fmt.Sprintf("Access token updated for %1s\n", *flagDstProfile))
}

func credsFilePath() (string, error) {
	if credsPath, ok := os.LookupEnv("AWS_SHARED_CREDENTIALS_FILE"); ok {
		return credsPath, nil
	}

	usr, err := user.Current()
	if err != nil {
		return "", err
	}
	return usr.HomeDir + "/.aws/credentials", nil
}

func configFilePath() (string, error) {
	if configPath, ok := os.LookupEnv("AWS_CONFIG_FILE"); ok {
		return configPath, nil
	}

	usr, err := user.Current()
	if err != nil {
		return "", err
	}

	return usr.HomeDir + "/.aws/config", nil
}

func findMfaDevices(sess *session.Session) (string, error) {
	config, err := configFilePath()
	if err != nil {
		return "", err
	}

	configIni, err := ini.Load(config)
	if err != nil {
		return "", err
	}
	definedMfaSerial, err := configIni.Section("profile " + *flagDstProfile).GetKey("mfa_serial")
	if err == nil {
		// We use what is defined by the users config file.
		logIt(fmt.Sprintf("Using device %1s\n", definedMfaSerial.String()))
		return definedMfaSerial.String(), nil
	}

	// If we doing get anything in the users config file we can try to get the
	// serial number from the source profile by looking what AWS has for the users.

	_iam := iam.New(sess)
	devices, err := _iam.ListMFADevices(&iam.ListMFADevicesInput{})

	if err != nil {
		return "", err
	}

	if len(devices.MFADevices) == 0 {
		return "", fmt.Errorf("no MFA devices configured")
	}

	serial := devices.MFADevices[0].SerialNumber

	logIt(fmt.Sprintf("Using device %1s\n", *serial))
	return *serial, nil
}

func collectStsCreds(sess *session.Session, mfaCode string) (map[string]string, error) {
	mfaSerial, err := findMfaDevices(sess)
	if err != nil {
		return nil, err
	}

	_sts := sts.New(sess)
	res, err := _sts.GetSessionToken(&sts.GetSessionTokenInput{
		TokenCode:    aws.String(mfaCode),
		SerialNumber: aws.String(mfaSerial),
	})

	if err != nil {
		return nil, err
	}

	return map[string]string{
		"aws_access_key_id":     *res.Credentials.AccessKeyId,
		"aws_secret_access_key": *res.Credentials.SecretAccessKey,
		"aws_session_token":     *res.Credentials.SessionToken,
		"mfa_expiration":        res.Credentials.Expiration.UTC().Format(time.RFC3339),
	}, nil
}

func writeCredentials(stsCreds map[string]string, srcProfile string, dstProfile string) error {
	credsFile, err := credsFilePath()
	if err != nil {
		return err
	}
	configFile, err := configFilePath()
	if err != nil {
		return err
	}

	credsFileIni, err := ini.Load(credsFile)
	if err != nil {
		return err
	}

	configFileIni, err := ini.Load(configFile)
	if err != nil {
		return err
	}

	// Write the credentials file
	credsFileIni.Section(*flagDstProfile).Key("aws_access_key_id").SetValue(stsCreds["aws_access_key_id"])
	credsFileIni.Section(*flagDstProfile).Key("aws_secret_access_key").SetValue(stsCreds["aws_secret_access_key"])
	credsFileIni.Section(*flagDstProfile).Key("aws_session_token").SetValue(stsCreds["aws_session_token"])
	err = credsFileIni.SaveTo(credsFile)
	if err != nil {
		return err
	}
	configFileIni.Section("profile " + *flagSrcProfile).Key("mfa_expiration").SetValue(stsCreds["mfa_expiration"])
	err = configFileIni.SaveTo(configFile)
	if err != nil {
		return err
	}

	return nil
}

func checkValidityTime(srcProfile string) error {
	configFile, err := configFilePath()
	if err != nil {
		log.Fatal(err)
	}

	configFileIni, err := ini.Load(configFile)
	if err != nil {
		log.Fatal(err)
	}

	expiration, err := configFileIni.Section("profile " + srcProfile).GetKey("mfa_expiration")
	if err != nil {
		log.Fatal(err)
	}

	expirationTime, err := time.Parse(time.RFC3339, expiration.String())
	if err != nil {
		return err
	}

	timeLeft := expirationTime.Unix() - time.Now().Unix()
	if timeLeft < 0 {
		logIt("Token expired.")
		os.Exit(1)
	} else {
		logIt(fmt.Sprintf("Token valid for %1d seconds\n", timeLeft))
	}
	return nil
}
