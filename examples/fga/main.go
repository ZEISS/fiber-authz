package main

import (
	"context"
	"encoding/json"
	"log"
	"os"

	openfga "github.com/openfga/go-sdk"
	"github.com/openfga/go-sdk/client"
)

func main() {
	fgaClient, err := client.NewSdkClient(&client.ClientConfiguration{
		ApiUrl:               os.Getenv("FGA_API_URL"),  // required, e.g. https://api.fga.example
		StoreId:              os.Getenv("FGA_STORE_ID"), // optional, not needed for \`CreateStore\` and \`ListStores\`, required before calling for all other methods
		AuthorizationModelId: os.Getenv("FGA_MODEL_ID"), // Optional, can be overridden per request
	})

	if err != nil {
		panic(err)
	}

	resp, err := fgaClient.CreateStore(context.Background()).Body(client.ClientCreateStoreRequest{Name: "Demo"}).Execute()
	if err != nil {
		panic(err)
	}

	log.Println(resp.Id)
	fgaClient.SetStoreId(resp.Id)

	// Read in example.json file into string.
	model, err := os.ReadFile("./examples/fga/example.json")
	if err != nil {
		panic(err)
	}

	var body openfga.WriteAuthorizationModelRequest
	if err := json.Unmarshal(model, &body); err != nil {
		panic(err)
	}

	data, err := fgaClient.WriteAuthorizationModel(context.Background()).
		Body(body).
		Execute()

	if err != nil {
		panic(err)
	}

	log.Println(data.AuthorizationModelId)

	options := client.ClientWriteOptions{
		AuthorizationModelId: openfga.PtrString(data.AuthorizationModelId),
	}

	writes := client.ClientWriteRequest{
		Writes: []client.ClientTupleKey{
			{
				User:     "team:zeiss",
				Relation: "team",
				Object:   "workload:foo",
			},
			{
				User:     "user:katallaxie",
				Relation: "editor",
				Object:   "team:zeiss",
			},
		},
	}

	write, err := fgaClient.Write(context.Background()).Body(writes).Options(options).Execute()
	if err != nil {
		panic(err)
	}

	log.Println(write.Writes)
}
