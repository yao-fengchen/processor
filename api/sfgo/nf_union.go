// Code generated by github.com/actgardner/gogen-avro/v7. DO NOT EDIT.
/*
 * SOURCES:
 *     GraphletRecord.avsc
 *     SysFlow.avsc
 */
package sfgo

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/actgardner/gogen-avro/v7/vm"
	"github.com/actgardner/gogen-avro/v7/vm/types"
)

type NfUnionTypeEnum int

const (
	NfUnionTypeEnumNetworkFlow NfUnionTypeEnum = 1
)

type NfUnion struct {
	Null        *types.NullVal
	NetworkFlow *NetworkFlow
	UnionType   NfUnionTypeEnum
}

func writeNfUnion(r *NfUnion, w io.Writer) error {

	if r == nil {
		err := vm.WriteLong(0, w)
		return err
	}

	err := vm.WriteLong(int64(r.UnionType), w)
	if err != nil {
		return err
	}
	switch r.UnionType {
	case NfUnionTypeEnumNetworkFlow:
		return writeNetworkFlow(r.NetworkFlow, w)
	}
	return fmt.Errorf("invalid value for *NfUnion")
}

func NewNfUnion() *NfUnion {
	return &NfUnion{}
}

func (_ *NfUnion) SetBoolean(v bool)   { panic("Unsupported operation") }
func (_ *NfUnion) SetInt(v int32)      { panic("Unsupported operation") }
func (_ *NfUnion) SetFloat(v float32)  { panic("Unsupported operation") }
func (_ *NfUnion) SetDouble(v float64) { panic("Unsupported operation") }
func (_ *NfUnion) SetBytes(v []byte)   { panic("Unsupported operation") }
func (_ *NfUnion) SetString(v string)  { panic("Unsupported operation") }
func (r *NfUnion) SetLong(v int64) {
	r.UnionType = (NfUnionTypeEnum)(v)
}
func (r *NfUnion) Get(i int) types.Field {
	switch i {
	case 0:
		return r.Null
	case 1:
		r.NetworkFlow = NewNetworkFlow()
		return r.NetworkFlow
	}
	panic("Unknown field index")
}
func (_ *NfUnion) NullField(i int)                  { panic("Unsupported operation") }
func (_ *NfUnion) SetDefault(i int)                 { panic("Unsupported operation") }
func (_ *NfUnion) AppendMap(key string) types.Field { panic("Unsupported operation") }
func (_ *NfUnion) AppendArray() types.Field         { panic("Unsupported operation") }
func (_ *NfUnion) Finalize()                        {}

func (r *NfUnion) MarshalJSON() ([]byte, error) {
	if r == nil {
		return []byte("null"), nil
	}
	switch r.UnionType {
	case NfUnionTypeEnumNetworkFlow:
		return json.Marshal(map[string]interface{}{"NetworkFlow": r.NetworkFlow})
	}
	return nil, fmt.Errorf("invalid value for *NfUnion")
}

func (r *NfUnion) UnmarshalJSON(data []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	if value, ok := fields["NetworkFlow"]; ok {
		r.UnionType = 1
		return json.Unmarshal([]byte(value), &r.NetworkFlow)
	}
	return fmt.Errorf("invalid value for *NfUnion")
}
