// Code generated by github.com/actgardner/gogen-avro/v7. DO NOT EDIT.
/*
 * SOURCE:
 *     SysFlow.avsc
 */
package sfgo

import (
	"io"

	"github.com/actgardner/gogen-avro/v7/compiler"
	"github.com/actgardner/gogen-avro/v7/vm"
	"github.com/actgardner/gogen-avro/v7/vm/types"
)

type SysFlow struct {
	Rec *RecUnion `json:"rec"`
}

const SysFlowAvroCRC64Fingerprint = "\xd2q3AӦJ("

func NewSysFlow() *SysFlow {
	return &SysFlow{}
}

func DeserializeSysFlow(r io.Reader) (*SysFlow, error) {
	t := NewSysFlow()
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

func DeserializeSysFlowFromSchema(r io.Reader, schema string) (*SysFlow, error) {
	t := NewSysFlow()

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

func writeSysFlow(r *SysFlow, w io.Writer) error {
	var err error
	err = writeRecUnion(r.Rec, w)
	if err != nil {
		return err
	}
	return err
}

func (r *SysFlow) Serialize(w io.Writer) error {
	return writeSysFlow(r, w)
}

func (r *SysFlow) Schema() string {
	return "{\"fields\":[{\"name\":\"rec\",\"type\":[{\"fields\":[{\"default\":4,\"name\":\"version\",\"type\":\"long\"},{\"name\":\"exporter\",\"type\":\"string\"},{\"default\":\"NA\",\"name\":\"ip\",\"type\":\"string\"},{\"name\":\"filename\",\"type\":\"string\"}],\"name\":\"SFHeader\",\"namespace\":\"sysflow.entity\",\"type\":\"record\"},{\"fields\":[{\"name\":\"id\",\"type\":\"string\"},{\"name\":\"name\",\"type\":\"string\"},{\"name\":\"image\",\"type\":\"string\"},{\"name\":\"imageid\",\"type\":\"string\"},{\"name\":\"mountsource\",\"type\":\"string\"},{\"name\":\"mountdest\",\"type\":\"string\"},{\"name\":\"mountmode\",\"type\":\"string\"},{\"name\":\"mountpropagation\",\"type\":\"string\"},{\"name\":\"type\",\"type\":{\"name\":\"ContainerType\",\"namespace\":\"sysflow.type\",\"symbols\":[\"CT_DOCKER\",\"CT_LXC\",\"CT_LIBVIRT_LXC\",\"CT_MESOS\",\"CT_RKT\",\"CT_CUSTOM\",\"CT_CRI\",\"CT_CONTAINERD\",\"CT_CRIO\",\"CT_BPM\"],\"type\":\"enum\"}},{\"name\":\"privileged\",\"type\":\"boolean\"},{\"name\":\"podId\",\"type\":[\"null\",\"string\"]}],\"name\":\"Container\",\"namespace\":\"sysflow.entity\",\"type\":\"record\"},{\"fields\":[{\"name\":\"state\",\"type\":{\"name\":\"SFObjectState\",\"namespace\":\"sysflow.type\",\"symbols\":[\"CREATED\",\"MODIFIED\",\"REUP\"],\"type\":\"enum\"}},{\"name\":\"oid\",\"type\":{\"fields\":[{\"name\":\"createTS\",\"type\":\"long\"},{\"name\":\"hpid\",\"type\":\"long\"}],\"name\":\"OID\",\"namespace\":\"sysflow.type\",\"type\":\"record\"}},{\"name\":\"poid\",\"type\":[\"null\",\"sysflow.type.OID\"]},{\"name\":\"ts\",\"type\":\"long\"},{\"name\":\"exe\",\"type\":\"string\"},{\"name\":\"exeArgs\",\"type\":\"string\"},{\"name\":\"uid\",\"type\":\"int\"},{\"name\":\"userName\",\"type\":\"string\"},{\"name\":\"gid\",\"type\":\"int\"},{\"name\":\"groupName\",\"type\":\"string\"},{\"name\":\"tty\",\"type\":\"boolean\"},{\"name\":\"containerId\",\"type\":[\"null\",\"string\"]},{\"default\":false,\"name\":\"entry\",\"type\":\"boolean\"}],\"name\":\"Process\",\"namespace\":\"sysflow.entity\",\"type\":\"record\"},{\"fields\":[{\"name\":\"state\",\"type\":\"sysflow.type.SFObjectState\"},{\"name\":\"oid\",\"type\":{\"name\":\"FOID\",\"namespace\":\"sysflow.type\",\"size\":20,\"type\":\"fixed\"}},{\"name\":\"ts\",\"type\":\"long\"},{\"name\":\"restype\",\"type\":\"int\"},{\"name\":\"path\",\"type\":\"string\"},{\"name\":\"containerId\",\"type\":[\"null\",\"string\"]}],\"name\":\"File\",\"namespace\":\"sysflow.entity\",\"type\":\"record\"},{\"fields\":[{\"name\":\"procOID\",\"type\":\"sysflow.type.OID\"},{\"name\":\"ts\",\"type\":\"long\"},{\"name\":\"tid\",\"type\":\"long\"},{\"name\":\"opFlags\",\"type\":\"int\"},{\"name\":\"args\",\"type\":{\"items\":\"string\",\"type\":\"array\"}},{\"name\":\"ret\",\"type\":\"int\"}],\"name\":\"ProcessEvent\",\"namespace\":\"sysflow.event\",\"type\":\"record\"},{\"fields\":[{\"name\":\"procOID\",\"type\":\"sysflow.type.OID\"},{\"name\":\"ts\",\"type\":\"long\"},{\"name\":\"tid\",\"type\":\"long\"},{\"name\":\"opFlags\",\"type\":\"int\"},{\"name\":\"endTs\",\"type\":\"long\"},{\"name\":\"sip\",\"type\":\"int\"},{\"name\":\"sport\",\"type\":\"int\"},{\"name\":\"dip\",\"type\":\"int\"},{\"name\":\"dport\",\"type\":\"int\"},{\"name\":\"proto\",\"type\":\"int\"},{\"name\":\"fd\",\"type\":\"int\"},{\"name\":\"numRRecvOps\",\"type\":\"long\"},{\"name\":\"numWSendOps\",\"type\":\"long\"},{\"name\":\"numRRecvBytes\",\"type\":\"long\"},{\"name\":\"numWSendBytes\",\"type\":\"long\"},{\"name\":\"gapTime\",\"type\":\"long\"},{\"name\":\"duration\",\"type\":\"long\"}],\"name\":\"NetworkFlow\",\"namespace\":\"sysflow.flow\",\"type\":\"record\"},{\"fields\":[{\"name\":\"procOID\",\"type\":\"sysflow.type.OID\"},{\"name\":\"ts\",\"type\":\"long\"},{\"name\":\"tid\",\"type\":\"long\"},{\"name\":\"opFlags\",\"type\":\"int\"},{\"name\":\"openFlags\",\"type\":\"int\"},{\"name\":\"endTs\",\"type\":\"long\"},{\"name\":\"fileOID\",\"type\":\"sysflow.type.FOID\"},{\"name\":\"fd\",\"type\":\"int\"},{\"name\":\"numRRecvOps\",\"type\":\"long\"},{\"name\":\"numWSendOps\",\"type\":\"long\"},{\"name\":\"numRRecvBytes\",\"type\":\"long\"},{\"name\":\"numWSendBytes\",\"type\":\"long\"},{\"name\":\"gapTime\",\"type\":\"long\"},{\"name\":\"duration\",\"type\":\"long\"}],\"name\":\"FileFlow\",\"namespace\":\"sysflow.flow\",\"type\":\"record\"},{\"fields\":[{\"name\":\"procOID\",\"type\":\"sysflow.type.OID\"},{\"name\":\"ts\",\"type\":\"long\"},{\"name\":\"tid\",\"type\":\"long\"},{\"name\":\"opFlags\",\"type\":\"int\"},{\"name\":\"fileOID\",\"type\":\"sysflow.type.FOID\"},{\"name\":\"ret\",\"type\":\"int\"},{\"name\":\"newFileOID\",\"type\":[\"null\",\"sysflow.type.FOID\"]}],\"name\":\"FileEvent\",\"namespace\":\"sysflow.event\",\"type\":\"record\"},{\"fields\":[{\"name\":\"procOID\",\"type\":\"sysflow.type.OID\"},{\"name\":\"ts\",\"type\":\"long\"},{\"name\":\"tid\",\"type\":\"long\"},{\"name\":\"opFlags\",\"type\":\"int\"},{\"name\":\"sip\",\"type\":\"int\"},{\"name\":\"sport\",\"type\":\"int\"},{\"name\":\"dip\",\"type\":\"int\"},{\"name\":\"dport\",\"type\":\"int\"},{\"name\":\"proto\",\"type\":\"int\"},{\"name\":\"ret\",\"type\":\"int\"}],\"name\":\"NetworkEvent\",\"namespace\":\"sysflow.event\",\"type\":\"record\"},{\"fields\":[{\"name\":\"procOID\",\"type\":\"sysflow.type.OID\"},{\"name\":\"ts\",\"type\":\"long\"},{\"name\":\"numThreadsCloned\",\"type\":\"long\"},{\"name\":\"opFlags\",\"type\":\"int\"},{\"name\":\"endTs\",\"type\":\"long\"},{\"name\":\"numThreadsExited\",\"type\":\"long\"},{\"name\":\"numCloneErrors\",\"type\":\"long\"}],\"name\":\"ProcessFlow\",\"namespace\":\"sysflow.flow\",\"type\":\"record\"},{\"fields\":[{\"name\":\"ts\",\"type\":\"long\"},{\"name\":\"id\",\"type\":\"string\"},{\"name\":\"name\",\"type\":\"string\"},{\"name\":\"nodeName\",\"type\":\"string\"},{\"name\":\"hostIP\",\"type\":{\"items\":\"long\",\"logicalType\":\"ipaddr\",\"type\":\"array\"}},{\"name\":\"internalIP\",\"type\":{\"items\":\"long\",\"logicalType\":\"ipaddr\",\"type\":\"array\"}},{\"name\":\"namespace\",\"type\":\"string\"},{\"name\":\"restartCount\",\"type\":\"long\"},{\"name\":\"labels\",\"type\":{\"type\":\"map\",\"values\":\"string\"}},{\"name\":\"selectors\",\"type\":{\"type\":\"map\",\"values\":\"string\"}},{\"name\":\"services\",\"type\":{\"items\":{\"fields\":[{\"name\":\"name\",\"type\":\"string\"},{\"name\":\"id\",\"type\":\"string\"},{\"name\":\"namespace\",\"type\":\"string\"},{\"name\":\"portList\",\"type\":{\"items\":{\"fields\":[{\"name\":\"port\",\"type\":\"int\"},{\"name\":\"targetPort\",\"type\":\"int\"},{\"name\":\"nodePort\",\"type\":\"int\"},{\"name\":\"proto\",\"type\":\"string\"}],\"name\":\"Port\",\"type\":\"record\"},\"type\":\"array\"}},{\"name\":\"clusterIP\",\"type\":{\"items\":\"long\",\"logicalType\":\"ipaddr\",\"type\":\"array\"}}],\"name\":\"Service\",\"type\":\"record\"},\"type\":\"array\"}}],\"name\":\"Pod\",\"namespace\":\"sysflow.entity\",\"type\":\"record\"},{\"fields\":[{\"name\":\"kind\",\"type\":{\"name\":\"K8sComponent\",\"namespace\":\"sysflow.type\",\"symbols\":[\"K8S_NODES\",\"K8S_NAMESPACES\",\"K8S_PODS\",\"K8S_REPLICATIONCONTROLLERS\",\"K8S_SERVICES\",\"K8S_EVENTS\",\"K8S_REPLICASETS\",\"K8S_DAEMONSETS\",\"K8S_DEPLOYMENTS\",\"K8S_UNKNOWN\"],\"type\":\"enum\"}},{\"name\":\"action\",\"type\":{\"name\":\"K8sAction\",\"namespace\":\"sysflow.type\",\"symbols\":[\"K8S_COMPONENT_ADDED\",\"K8S_COMPONENT_MODIFIED\",\"K8S_COMPONENT_DELETED\",\"K8S_COMPONENT_ERROR\",\"K8S_COMPONENT_NONEXISTENT\",\"K8S_COMPONENT_UNKNOWN\"],\"type\":\"enum\"}},{\"name\":\"ts\",\"type\":\"long\"},{\"name\":\"message\",\"type\":\"string\"}],\"name\":\"K8sEvent\",\"namespace\":\"sysflow.event\",\"type\":\"record\"}]}],\"name\":\"sysflow.SysFlow\",\"type\":\"record\"}"
}

func (r *SysFlow) SchemaName() string {
	return "sysflow.SysFlow"
}

func (_ *SysFlow) SetBoolean(v bool)    { panic("Unsupported operation") }
func (_ *SysFlow) SetInt(v int32)       { panic("Unsupported operation") }
func (_ *SysFlow) SetLong(v int64)      { panic("Unsupported operation") }
func (_ *SysFlow) SetFloat(v float32)   { panic("Unsupported operation") }
func (_ *SysFlow) SetDouble(v float64)  { panic("Unsupported operation") }
func (_ *SysFlow) SetBytes(v []byte)    { panic("Unsupported operation") }
func (_ *SysFlow) SetString(v string)   { panic("Unsupported operation") }
func (_ *SysFlow) SetUnionElem(v int64) { panic("Unsupported operation") }

func (r *SysFlow) Get(i int) types.Field {
	switch i {
	case 0:
		r.Rec = NewRecUnion()

		return r.Rec
	}
	panic("Unknown field index")
}

func (r *SysFlow) SetDefault(i int) {
	switch i {
	}
	panic("Unknown field index")
}

func (r *SysFlow) NullField(i int) {
	switch i {
	}
	panic("Not a nullable field index")
}

func (_ *SysFlow) AppendMap(key string) types.Field { panic("Unsupported operation") }
func (_ *SysFlow) AppendArray() types.Field         { panic("Unsupported operation") }
func (_ *SysFlow) Finalize()                        {}

func (_ *SysFlow) AvroCRC64Fingerprint() []byte {
	return []byte(SysFlowAvroCRC64Fingerprint)
}
