// Code generated by github.com/actgardner/gogen-avro/v7. DO NOT EDIT.
/*
 * SOURCE:
 *     SysFlow.avsc
 */
package sfgo

import (
	"github.com/actgardner/gogen-avro/v7/compiler"
	"github.com/actgardner/gogen-avro/v7/vm"
	"github.com/actgardner/gogen-avro/v7/vm/types"
	"io"
)

type Container struct {
	Id string `json:"id"`

	Name string `json:"name"`

	Image string `json:"image"`

	Imageid string `json:"imageid"`

	Imagerepo string `json:"imagerepo"`

	MountSource string `json:"mountsource"`

	MountDest string `json:"mountdest"`

	MountMode string `json:"mountmode"`

	MountPropagation string `json:"mountpropagation"`

	HostPort string `json:"hostport"`

	ContainerPort string `json:"containerport"`

	Type ContainerType `json:"type"`

	Privileged bool `json:"privileged"`

	PodId *PodIdUnion `json:"podId"`
}

const ContainerAvroCRC64Fingerprint = "\xbav\xfc\f\x9bU\xc8\xcd"

func NewContainer() *Container {
	return &Container{}
}

func DeserializeContainer(r io.Reader) (*Container, error) {
	t := NewContainer()
	deser, err := compiler.CompileSchemaBytes([]byte(t.Schema()), []byte(t.Schema()))
	if err != nil {
		return nil, err
	}

	err = vm.Eval(r, deser, t)
	if err != nil {
		return nil, err
	}
	return t, err
}

func DeserializeContainerFromSchema(r io.Reader, schema string) (*Container, error) {
	t := NewContainer()

	deser, err := compiler.CompileSchemaBytes([]byte(schema), []byte(t.Schema()))
	if err != nil {
		return nil, err
	}

	err = vm.Eval(r, deser, t)
	if err != nil {
		return nil, err
	}
	return t, err
}

func writeContainer(r *Container, w io.Writer) error {
	var err error
	err = vm.WriteString(r.Id, w)
	if err != nil {
		return err
	}
	err = vm.WriteString(r.Name, w)
	if err != nil {
		return err
	}
	err = vm.WriteString(r.Image, w)
	if err != nil {
		return err
	}
	err = vm.WriteString(r.Imageid, w)
	if err != nil {
		return err
	}
	err = vm.WriteString(r.Imagerepo, w)
	if err != nil {
		return err
	}
	err = vm.WriteString(r.MountSource, w)
	if err != nil {
		return err
	}
	err = vm.WriteString(r.MountDest, w)
	if err != nil {
		return err
	}
	err = vm.WriteString(r.MountMode, w)
	if err != nil {
		return err
	}
	err = vm.WriteString(r.MountPropagation, w)
	if err != nil {
		return err
	}
	err = vm.WriteString(r.HostPort, w)
	if err != nil {
		return err
	}
	err = vm.WriteString(r.ContainerPort, w)
	if err != nil {
		return err
	}
	err = writeContainerType(r.Type, w)
	if err != nil {
		return err
	}
	err = vm.WriteBool(r.Privileged, w)
	if err != nil {
		return err
	}
	err = writePodIdUnion(r.PodId, w)
	if err != nil {
		return err
	}
	return err
}

func (r *Container) Serialize(w io.Writer) error {
	return writeContainer(r, w)
}

func (r *Container) Schema() string {
	return "{\"fields\":[{\"name\":\"id\",\"type\":\"string\"},{\"name\":\"name\",\"type\":\"string\"},{\"name\":\"image\",\"type\":\"string\"},{\"name\":\"imageid\",\"type\":\"string\"},{\"name\":\"imagerepo\",\"type\":\"string\"},{\"name\":\"mountsource\",\"type\":\"string\"},{\"name\":\"mountdest\",\"type\":\"string\"},{\"name\":\"mountmode\",\"type\":\"string\"},{\"name\":\"mountpropagation\",\"type\":\"string\"},{\"name\":\"hostport\",\"type\":\"string\"},{\"name\":\"containerport\",\"type\":\"string\"},{\"name\":\"type\",\"type\":{\"name\":\"ContainerType\",\"namespace\":\"sysflow.type\",\"symbols\":[\"CT_DOCKER\",\"CT_LXC\",\"CT_LIBVIRT_LXC\",\"CT_MESOS\",\"CT_RKT\",\"CT_CUSTOM\",\"CT_CRI\",\"CT_CONTAINERD\",\"CT_CRIO\",\"CT_BPM\"],\"type\":\"enum\"}},{\"name\":\"privileged\",\"type\":\"boolean\"},{\"name\":\"podId\",\"type\":[\"null\",\"string\"]}],\"name\":\"sysflow.entity.Container\",\"type\":\"record\"}"
}

func (r *Container) SchemaName() string {
	return "sysflow.entity.Container"
}

func (_ *Container) SetBoolean(v bool)    { panic("Unsupported operation") }
func (_ *Container) SetInt(v int32)       { panic("Unsupported operation") }
func (_ *Container) SetLong(v int64)      { panic("Unsupported operation") }
func (_ *Container) SetFloat(v float32)   { panic("Unsupported operation") }
func (_ *Container) SetDouble(v float64)  { panic("Unsupported operation") }
func (_ *Container) SetBytes(v []byte)    { panic("Unsupported operation") }
func (_ *Container) SetString(v string)   { panic("Unsupported operation") }
func (_ *Container) SetUnionElem(v int64) { panic("Unsupported operation") }

func (r *Container) Get(i int) types.Field {
	switch i {
	case 0:
		return &types.String{Target: &r.Id}
	case 1:
		return &types.String{Target: &r.Name}
	case 2:
		return &types.String{Target: &r.Image}
	case 3:
		return &types.String{Target: &r.Imageid}
	case 4:
		return &types.String{Target: &r.Imagerepo}
	case 5:
		return &types.String{Target: &r.MountSource}
	case 6:
		return &types.String{Target: &r.MountDest}
	case 7:
		return &types.String{Target: &r.MountMode}
	case 8:
		return &types.String{Target: &r.MountPropagation}
	case 9:
		return &types.String{Target: &r.HostPort}
	case 10:
		return &types.String{Target: &r.ContainerPort}
	case 11:
		return &ContainerTypeWrapper{Target: &r.Type}
	case 12:
		return &types.Boolean{Target: &r.Privileged}
	case 13:
		r.PodId = NewPodIdUnion()

		return r.PodId
	}
	panic("Unknown field index")
}

func (r *Container) SetDefault(i int) {
	switch i {
	}
	panic("Unknown field index")
}

func (r *Container) NullField(i int) {
	switch i {
	case 6:
		r.PodId = nil
		return
	}
	panic("Not a nullable field index")
}

func (_ *Container) AppendMap(key string) types.Field { panic("Unsupported operation") }
func (_ *Container) AppendArray() types.Field         { panic("Unsupported operation") }
func (_ *Container) Finalize()                        {}

func (_ *Container) AvroCRC64Fingerprint() []byte {
	return []byte(ContainerAvroCRC64Fingerprint)
}
