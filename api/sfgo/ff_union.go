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

type FfUnionTypeEnum int

const (
	FfUnionTypeEnumFileFlow FfUnionTypeEnum = 1
)

type FfUnion struct {
	Null      *types.NullVal
	FileFlow  *FileFlow
	UnionType FfUnionTypeEnum
}

func writeFfUnion(r *FfUnion, w io.Writer) error {

	if r == nil {
		err := vm.WriteLong(0, w)
		return err
	}

	err := vm.WriteLong(int64(r.UnionType), w)
	if err != nil {
		return err
	}
	switch r.UnionType {
	case FfUnionTypeEnumFileFlow:
		return writeFileFlow(r.FileFlow, w)
	}
	return fmt.Errorf("invalid value for *FfUnion")
}

func NewFfUnion() *FfUnion {
	return &FfUnion{}
}

func (_ *FfUnion) SetBoolean(v bool)   { panic("Unsupported operation") }
func (_ *FfUnion) SetInt(v int32)      { panic("Unsupported operation") }
func (_ *FfUnion) SetFloat(v float32)  { panic("Unsupported operation") }
func (_ *FfUnion) SetDouble(v float64) { panic("Unsupported operation") }
func (_ *FfUnion) SetBytes(v []byte)   { panic("Unsupported operation") }
func (_ *FfUnion) SetString(v string)  { panic("Unsupported operation") }
func (r *FfUnion) SetLong(v int64) {
	r.UnionType = (FfUnionTypeEnum)(v)
}
func (r *FfUnion) Get(i int) types.Field {
	switch i {
	case 0:
		return r.Null
	case 1:
		r.FileFlow = NewFileFlow()
		return r.FileFlow
	}
	panic("Unknown field index")
}
func (_ *FfUnion) NullField(i int)                  { panic("Unsupported operation") }
func (_ *FfUnion) SetDefault(i int)                 { panic("Unsupported operation") }
func (_ *FfUnion) AppendMap(key string) types.Field { panic("Unsupported operation") }
func (_ *FfUnion) AppendArray() types.Field         { panic("Unsupported operation") }
func (_ *FfUnion) Finalize()                        {}

func (r *FfUnion) MarshalJSON() ([]byte, error) {
	if r == nil {
		return []byte("null"), nil
	}
	switch r.UnionType {
	case FfUnionTypeEnumFileFlow:
		return json.Marshal(map[string]interface{}{"FileFlow": r.FileFlow})
	}
	return nil, fmt.Errorf("invalid value for *FfUnion")
}

func (r *FfUnion) UnmarshalJSON(data []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	if value, ok := fields["FileFlow"]; ok {
		r.UnionType = 1
		return json.Unmarshal([]byte(value), &r.FileFlow)
	}
	return fmt.Errorf("invalid value for *FfUnion")
}