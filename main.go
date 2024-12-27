package main

import (
	"fmt"

	"github.com/google/uuid"
)

type UserID = uuid.UUID

type MessageID = uuid.UUID

type MessagePayload struct {
	PreviousMessageHash []byte // nil for the first message
	Content             string
}

type Message struct {
	Sender    UserID
	Receiver  UserID
	Payload   []byte // Serialized `MessagePayload`
	Signature []byte // Signature of `Payload`
}

func main() {
	fmt.Println("You should run:")
	fmt.Println("\tgo test .        # to check for correctness")
	fmt.Println("\tgo test -bench=. # to check for performance")
}
