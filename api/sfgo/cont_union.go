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

type ContUnionTypeEnum int

const (
	ContUnionTypeEnumContainer ContUnionTypeEnum = 1
)

type ContUnion struct {
	Null      *types.NullVal
	Container *Container
	UnionType ContUnionTypeEnum
}

func writeContUnion(r *ContUnion, w io.Writer) error {

	if r == nil {
		err := vm.WriteLong(0, w)
		return err
	}

	err := vm.WriteLong(int64(r.UnionType), w)
	if err != nil {
		return err
	}
	switch r.UnionType {
	case ContUnionTypeEnumContainer:
		return writeContainer(r.Container, w)
	}
	return fmt.Errorf("invalid value for *ContUnion")
}

func NewContUnion() *ContUnion {
	return &ContUnion{}
}

func (_ *ContUnion) SetBoolean(v bool)   { panic("Unsupported operation") }
func (_ *ContUnion) SetInt(v int32)      { panic("Unsupported operation") }
func (_ *ContUnion) SetFloat(v float32)  { panic("Unsupported operation") }
func (_ *ContUnion) SetDouble(v float64) { panic("Unsupported operation") }
func (_ *ContUnion) SetBytes(v []byte)   { panic("Unsupported operation") }
func (_ *ContUnion) SetString(v string)  { panic("Unsupported operation") }
func (r *ContUnion) SetLong(v int64) {
	r.UnionType = (ContUnionTypeEnum)(v)
}
func (r *ContUnion) Get(i int) types.Field {
	switch i {
	case 0:
		return r.Null
	case 1:
		r.Container = NewContainer()
		return r.Container
	}
	panic("Unknown field index")
}
func (_ *ContUnion) NullField(i int)                  { panic("Unsupported operation") }
func (_ *ContUnion) SetDefault(i int)                 { panic("Unsupported operation") }
func (_ *ContUnion) AppendMap(key string) types.Field { panic("Unsupported operation") }
func (_ *ContUnion) AppendArray() types.Field         { panic("Unsupported operation") }
func (_ *ContUnion) Finalize()                        {}

func (r *ContUnion) MarshalJSON() ([]byte, error) {
	if r == nil {
		return []byte("null"), nil
	}
	switch r.UnionType {
	case ContUnionTypeEnumContainer:
		return json.Marshal(map[string]interface{}{"Container": r.Container})
	}
	return nil, fmt.Errorf("invalid value for *ContUnion")
}

func (r *ContUnion) UnmarshalJSON(data []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	if value, ok := fields["Container"]; ok {
		r.UnionType = 1
		return json.Unmarshal([]byte(value), &r.Container)
	}
	return fmt.Errorf("invalid value for *ContUnion")
}
