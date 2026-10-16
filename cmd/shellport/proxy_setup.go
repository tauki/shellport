package main

import (
	"flag"
	"fmt"
	"strings"

	"shellport/internal/shellport"
)

type proxyAddresses []string

func (p *proxyAddresses) String() string { return strings.Join(*p, ",") }
func (p *proxyAddresses) Set(value string) error {
	if err := shellport.ValidateTrustedProxies([]string{value}); err != nil {
		return err
	}
	*p = append(*p, value)
	return nil
}

func runProxySetup(args []string) error {
	flags := flag.NewFlagSet("setup-proxy", flag.ContinueOnError)
	dir := flags.String("data-dir", ".data", "existing private persistent data directory")
	var proxies proxyAddresses
	flags.Var(&proxies, "trusted-proxy", "trusted reverse-proxy source IP or CIDR; repeat to replace the complete list")
	clear := flags.Bool("clear", false, "remove all proxy trust; requests with forwarding headers will be rejected")
	flags.Usage = func() {
		fmt.Fprintln(flags.Output(), "Configure trusted reverse-proxy addresses while Shellport is stopped.\nSupply the proxy's TCP source addresses, not browser addresses. Every process able to connect from a trusted address can supply forwarding headers.")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments")
	}
	if (*clear && len(proxies) > 0) || (!*clear && len(proxies) == 0) {
		return fmt.Errorf("choose one or more --trusted-proxy addresses, or --clear to remove proxy trust")
	}
	if err := shellport.ConfigureTrustedProxies(*dir, proxies); err != nil {
		return err
	}
	fmt.Println("Trusted proxy addresses saved. Start Shellport to use the updated configuration.")
	return nil
}
