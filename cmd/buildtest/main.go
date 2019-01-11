package main

import (
	"github.com/j-forristal/strongcomms"
)

func main() {

	cfg := strongcomms.Config{
		UseCloudflareDOH: true,
		UseGoogleDOH:     true,
	}

	client, err := strongcomms.New(cfg)
	if err != nil {
		panic(err)
	}

	_, err = client.LookupIP("www.forristal.com")
	if err != nil {
		panic(err)
	}
}
