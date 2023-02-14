// Package encoders implements codecs for exporting records and events in different data formats.
package encoders

import (
	"encoding/binary"
	"fmt"
	"net"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cespare/xxhash/v2"
	"github.com/satta/gommunityid"
	"github.com/sysflow-telemetry/sf-apis/go/sfgo"
	"github.com/sysflow-telemetry/sf-processor/core/exporter/commons"
	"github.com/sysflow-telemetry/sf-processor/core/exporter/utils"
	"github.com/sysflow-telemetry/sf-processor/core/policyengine/engine"
	"github.com/tidwall/gjson"
)

// JSONData is a map to serialize data to JSON.
type JSONData map[string]interface{}

// ECSRecord is a struct for serializing ECS records.
type ECSRecord struct {
	ID    string `json:"-"`
	Ts    string `json:"timestamp"`
	Head		 JSONData	`json:"head"`
	Event        JSONData   `json:"event"`
	Host         JSONData   `json:"host"`
	Container    JSONData   `json:"container,omitempty"`
	Orchestrator JSONData   `json:"orchestrator,omitempty"`
	Pod          JSONData   `json:"pod,omitempty"`
	Service      []JSONData `json:"service,omitempty"`
	File         JSONData   `json:"file,omitempty"`
	FileAction   JSONData   `json:"file_action,omitempty"`
	Network      JSONData   `json:"network,omitempty"`
	Source       JSONData   `json:"source,omitempty"`
	Destination  JSONData   `json:"destination,omitempty"`
	PProcess	 JSONData	`json:"pprocess,omitempty"`
	Process      JSONData   `json:"process,omitempty"`
	Tags         []string   `json:"tags,omitempty"`
}

// ECSEncoder implements an ECS encoder for telemetry records.
type ECSEncoder struct {
	config commons.Config
	//jsonencoder JSONEncoder
	batch []commons.EncodedData
}

// NewECSEncoder instantiates an ECS encoder.
func NewECSEncoder(config commons.Config) Encoder {
	return &ECSEncoder{
		config: config,
		batch:  make([]commons.EncodedData, 0, config.EventBuffer)}
}

// Register registers the encoder to the codecs cache.
func (t *ECSEncoder) Register(codecs map[commons.Format]EncoderFactory) {
	codecs[commons.ECSFormat] = NewECSEncoder
}

// Encode encodes telemetry records into an ECS representation.
func (t *ECSEncoder) Encode(recs []*engine.Record) ([]commons.EncodedData, error) {
	t.batch = t.batch[:0]
	for _, rec := range recs {
		ecs := t.encode(rec)
		t.batch = append(t.batch, ecs)
	}
	return t.batch, nil
}

// Encodes a telemetry record into an ECS representation.
func (t *ECSEncoder) encode(rec *engine.Record) *ECSRecord {
	ecs := &ECSRecord{
		ID:   encodeID(rec),
		Host: encodeHost(rec),
		Head: encodeHead(rec),
	}
	ecs.Ts = utils.ToIsoTimeStr(engine.Mapper.MapInt(engine.SF_TS)(rec))

	// encode specific record components
	sfType := engine.Mapper.MapStr(engine.SF_TYPE)(rec)
	if sfType != sfgo.TyKEStr {
		ecs.Container = encodeContainer(rec)
		if engine.Mapper.MapStr(engine.SF_POD_ID)(rec) != sfgo.Zeros.String {
			ecs.encodeOrchestrator(rec)
			ecs.encodePod(rec)
		}
		ecs.Process = encodeProcess(rec)
		ecs.PProcess = encodePProcess(rec)
	} else {
		ecs.encodeOrchestrator(rec)
	}

	switch sfType {
	case sfgo.TyNFStr:
		ecs.encodeNetworkFlow(rec)
	case sfgo.TyFFStr:
		ecs.encodeFileFlow(rec)
	case sfgo.TyFEStr:
		ecs.encodeFileEvent(rec)
	case sfgo.TyPEStr:
		ecs.encodeProcessEvent(rec)
	case sfgo.TyKEStr:
		ecs.encodeK8sEvent(rec)
	}

	// encode tags and policy information
	tags := rec.Ctx.GetTags()
	rules := rec.Ctx.GetRules()
	if len(rules) > 0 {
		reasons := make([]string, 0)
		priority := int(engine.Low)
		for _, r := range rules {
			reasons = append(reasons, r.Name)
			tags = append(tags, extracTags(r.Tags)...)
			priority = utils.Max(priority, int(r.Priority))
		}
		ecs.Event[ECS_EVENT_REASON] = strings.Join(reasons, ", ")
		ecs.Event[ECS_EVENT_SEVERITY] = priority
	}
	if len(tags) > 0 {
		ecs.Tags = tags
	}

	return ecs
}

var byteInt64 []byte = make([]byte, 8)

// encodeID returns the ECS document identifier.
func encodeID(rec *engine.Record) string {
	h := xxhash.New()
	t := engine.Mapper.MapStr(engine.SF_TYPE)(rec)
	h.Write([]byte(engine.Mapper.MapStr(engine.SF_NODE_ID)(rec)))
	h.Write([]byte(engine.Mapper.MapStr(engine.SF_CONTAINER_ID)(rec)))
	binary.LittleEndian.PutUint64(byteInt64, uint64(rec.GetInt(sfgo.TS_INT, sfgo.SYSFLOW_SRC)))
	h.Write(byteInt64)
	binary.LittleEndian.PutUint64(byteInt64, uint64(rec.GetInt(sfgo.TID_INT, sfgo.SYSFLOW_SRC)))
	h.Write(byteInt64)
	binary.LittleEndian.PutUint64(byteInt64, uint64(rec.GetInt(sfgo.PROC_OID_CREATETS_INT, sfgo.SYSFLOW_SRC)))
	h.Write(byteInt64)
	binary.LittleEndian.PutUint64(byteInt64, uint64(rec.GetInt(sfgo.EV_PROC_OPFLAGS_INT, sfgo.SYSFLOW_SRC)))
	h.Write(byteInt64)
	switch t {
	case sfgo.TyFFStr, sfgo.TyFEStr:
		h.Write([]byte(engine.Mapper.MapStr(engine.SF_FILE_OID)(rec)))
	case sfgo.TyNFStr:
		binary.LittleEndian.PutUint64(byteInt64, uint64(rec.GetInt(sfgo.FL_NETW_SIP_INT, sfgo.SYSFLOW_SRC)))
		h.Write(byteInt64)
		binary.LittleEndian.PutUint64(byteInt64, uint64(rec.GetInt(sfgo.FL_NETW_SPORT_INT, sfgo.SYSFLOW_SRC)))
		h.Write(byteInt64)
		binary.LittleEndian.PutUint64(byteInt64, uint64(rec.GetInt(sfgo.FL_NETW_DIP_INT, sfgo.SYSFLOW_SRC)))
		h.Write(byteInt64)
		binary.LittleEndian.PutUint64(byteInt64, uint64(rec.GetInt(sfgo.FL_NETW_DPORT_INT, sfgo.SYSFLOW_SRC)))
		h.Write(byteInt64)
		binary.LittleEndian.PutUint64(byteInt64, uint64(rec.GetInt(sfgo.FL_NETW_PROTO_INT, sfgo.SYSFLOW_SRC)))
		h.Write(byteInt64)
	case sfgo.TyKEStr:
		binary.LittleEndian.PutUint64(byteInt64, uint64(rec.GetInt(sfgo.K8SE_ACTION_INT, sfgo.SYSFLOW_SRC)))
		h.Write(byteInt64)
		binary.LittleEndian.PutUint64(byteInt64, uint64(rec.GetInt(sfgo.K8SE_KIND_INT, sfgo.SYSFLOW_SRC)))
		h.Write(byteInt64)
		h.Write([]byte(engine.Mapper.MapStr(engine.SF_K8SE_MESSAGE)(rec)))
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

// encodeNetworkFlow populates the ECS representatiom of a NetworkFlow record.
func (ecs *ECSRecord) encodeNetworkFlow(rec *engine.Record) {
	rbytes := engine.Mapper.MapInt(engine.SF_FLOW_RBYTES)(rec)
	rops := engine.Mapper.MapInt(engine.SF_FLOW_ROPS)(rec)
	wbytes := engine.Mapper.MapInt(engine.SF_FLOW_WBYTES)(rec)
	wops := engine.Mapper.MapInt(engine.SF_FLOW_WOPS)(rec)
	gaptime := engine.Mapper.MapInt(engine.SF_FLOW_GAPTIME)(rec)
	dutation := engine.Mapper.MapInt(engine.SF_FLOW_DURATION)(rec)
	sip := engine.Mapper.MapStr(engine.SF_NET_SIP)(rec)
	dip := engine.Mapper.MapStr(engine.SF_NET_DIP)(rec)
	sport := engine.Mapper.MapInt(engine.SF_NET_SPORT)(rec)
	dport := engine.Mapper.MapInt(engine.SF_NET_DPORT)(rec)
	proto := engine.Mapper.MapInt(engine.SF_NET_PROTO)(rec)
	// shostname := engine.Mapper.MapStr(engine.SF_NET_SOURCE_HOST_NAME)(rec)
	// dhostname := engine.Mapper.MapStr(engine.SF_NET_DEST_HOST_NAME)(rec)

	cid, _ := gommunityid.GetCommunityIDByVersion(1, 0)
	ft := gommunityid.MakeFlowTuple(net.ParseIP(sip), net.ParseIP(dip), uint16(sport), uint16(dport), uint8(proto))

	// Calculate Base64-encoded value
	ecs.Network = JSONData{
		ECS_NET_RBYTES:  rbytes,
		ECS_NET_WBYTES:  wbytes,
		ECS_NET_CID:     cid.CalcBase64(ft),
		ECS_NET_IANA:    strconv.FormatInt(proto, 10),
		ECS_NET_PROTO: 	 sfgo.GetProto(proto),
		ECS_NET_GAPTIME: gaptime,
		ECS_NET_DURATION:dutation,
		// "shostname": shostname,
		// "dhostname": dhostname,
	}
	ecs.Source = JSONData{
		ECS_ENDPOINT_IP:      sip,
		ECS_ENDPOINT_PORT:    sport,
		ECS_ENDPOINT_BYTES:   wbytes,
		ECS_ENDPOINT_PACKETS: wops,
	}
	ecs.Destination = JSONData{
		ECS_ENDPOINT_IP:      dip,
		ECS_ENDPOINT_PORT:    dport,
		ECS_ENDPOINT_BYTES:   rbytes,
		ECS_ENDPOINT_PACKETS: rops,
	}
	ecs.Event = encodeEvent(rec, ECS_CAT_NETWORK, ECS_TYPE_CONNECTION, ECS_CAT_NETWORK+"-"+ECS_ACTION_TRAFFIC)
}

// encodeFileFlow populates the ECS representatiom of a FF record
func (ecs *ECSRecord) encodeFileFlow(rec *engine.Record) {
	opFlags := rec.GetInt(sfgo.EV_PROC_OPFLAGS_INT, sfgo.SYSFLOW_SRC)
	rbytes := engine.Mapper.MapInt(engine.SF_FLOW_RBYTES)(rec)
	rops := engine.Mapper.MapInt(engine.SF_FLOW_ROPS)(rec)
	wbytes := engine.Mapper.MapInt(engine.SF_FLOW_WBYTES)(rec)
	wops := engine.Mapper.MapInt(engine.SF_FLOW_WOPS)(rec)
	gaptime := engine.Mapper.MapInt(engine.SF_FLOW_GAPTIME)(rec)
	duration := engine.Mapper.MapInt(engine.SF_FLOW_DURATION)(rec)
	category := ECS_CAT_FILE
	eventType := ECS_TYPE_ACCESS
	action := category + "-" + eventType
	if opFlags&sfgo.OP_READ_RECV == sfgo.OP_READ_RECV && (rbytes > 0 || rops > 0) {
		action = action + "-" + ECS_ACTION_READ
	}
	if opFlags&sfgo.OP_WRITE_SEND == sfgo.OP_WRITE_SEND && (wbytes > 0 || wops > 0) {
		eventType = ECS_TYPE_CHANGE
		action = action + "-" + ECS_ACTION_WRITE
	}
	ecs.Event = encodeEvent(rec, category, eventType, action)
	ecs.File = encodeFile(rec)
	if rbytes > 0 || rops > 0 || wbytes > 0 || wops > 0 || gaptime > 0 {
		ecs.FileAction = JSONData{
			ECS_SF_FA_RBYTES:  rbytes,
			ECS_SF_FA_ROPS:    rops,
			ECS_SF_FA_WBYTES:  wbytes,
			ECS_SF_FA_WOPS:    wops,
			ECS_SF_FA_GAPTIME: gaptime,
			ECS_SF_FA_DURATION:duration,
		}
	}
}

// encodeFileEvent populates the ECS representatiom of a FE record
func (ecs *ECSRecord) encodeFileEvent(rec *engine.Record) {
	opFlags := rec.GetInt(sfgo.EV_PROC_OPFLAGS_INT, sfgo.SYSFLOW_SRC)
	targetPath := engine.Mapper.MapStr(engine.SF_FILE_NEWPATH)(rec)
	ecs.File = encodeFile(rec)
	category := ECS_CAT_FILE
	eventType := ECS_TYPE_CHANGE
	action := category + "-" + eventType
	if opFlags&sfgo.OP_MKDIR == sfgo.OP_MKDIR {
		category = ECS_CAT_DIR
		eventType = ECS_TYPE_CREATE
		action = category + "-" + ECS_ACTION_CREATE
	} else if opFlags&sfgo.OP_RMDIR == sfgo.OP_RMDIR {
		category = ECS_CAT_DIR
		eventType = ECS_TYPE_DELETE
		action = category + "-" + ECS_ACTION_DELETE
	} else if opFlags&sfgo.OP_UNLINK == sfgo.OP_UNLINK {
		eventType = ECS_TYPE_DELETE
		action = category + "-" + ECS_ACTION_DELETE
	} else if opFlags&sfgo.OP_SYMLINK == sfgo.OP_SYMLINK || opFlags&sfgo.OP_LINK == sfgo.OP_LINK {
		action = category + "-" + ECS_ACTION_LINK
		ecs.File[ECS_FILE_TARGET] = targetPath
	} else if opFlags&sfgo.OP_RENAME == sfgo.OP_RENAME {
		action = category + "-" + ECS_ACTION_RENAME
		ecs.File[ECS_FILE_TARGET] = targetPath
	}
	ecs.Event = encodeEvent(rec, category, eventType, action)
}

// encodeProcessEvent populates the ECS representatiom of a PE record
func (ecs *ECSRecord) encodeProcessEvent(rec *engine.Record) {
	opFlags := rec.GetInt(sfgo.EV_PROC_OPFLAGS_INT, sfgo.SYSFLOW_SRC)
	pid := engine.Mapper.MapInt(engine.SF_PROC_PID)(rec)
	tid := engine.Mapper.MapInt(engine.SF_PROC_TID)(rec)
	// tty := engine.Mapper.MapInt(engine.SF_PROC_TTY)
	category := ECS_CAT_PROCESS
	eventType := ECS_TYPE_START

	if opFlags&sfgo.OP_EXIT == sfgo.OP_EXIT {
		if pid != tid {
			eventType = ECS_TYPE_TEXIT
		} else {
			eventType = ECS_TYPE_EXIT
		}
	} else if opFlags&sfgo.OP_CLONE == sfgo.OP_CLONE || opFlags&sfgo.OP_EXEC == sfgo.OP_EXEC {
		if pid != tid {
			eventType = ECS_TYPE_TSTART
		}
	} else if opFlags&sfgo.OP_SETUID == sfgo.OP_SETUID {
		eventType = ECS_TYPE_CHANGE
	}

	action := category + "-" + eventType
	ecs.Event = encodeEvent(rec, category, eventType, action)
}

func k8sActionToEventType(rec *engine.Record) string {
	eventType := ECS_TYPE_INFO
	am := engine.Mapper.Mappers[engine.SF_K8SE_ACTION]
	switch sfgo.K8sAction(rec.Fr.Ints[am.Source][am.FlatIndex]) {
	case sfgo.K8sActionK8S_COMPONENT_ADDED:
		eventType = ECS_TYPE_CREATE
	case sfgo.K8sActionK8S_COMPONENT_DELETED:
		eventType = ECS_TYPE_DELETE
	case sfgo.K8sActionK8S_COMPONENT_MODIFIED:
		eventType = ECS_TYPE_CHANGE
	case sfgo.K8sActionK8S_COMPONENT_ERROR:
		eventType = ECS_TYPE_ERROR
	}
	return eventType
}

// encodeK8sEvent populates the ECS representatiom of a KE record
func (ecs *ECSRecord) encodeK8sEvent(rec *engine.Record) {
	category := ECS_CAT_ORCH
	eventType := k8sActionToEventType(rec)
	action := engine.Mapper.MapStr(engine.SF_K8SE_ACTION)(rec)

	ecs.Event = encodeEvent(rec, category, eventType, action)
	msgStr := engine.Mapper.MapStr(engine.SF_K8SE_MESSAGE)(rec)
	ecs.Event[ECS_EVENT_ORIGINAL] = msgStr

	msg := gjson.Parse(msgStr)
	ecs.Orchestrator = JSONData{
		ECS_ORCHESTRATOR_NAMESPACE: msg.Get("items.0.namespace").String(),
		ECS_ORCHESTRATOR_RESOURCE: JSONData{
			ECS_RESOURCE_TYPE: strings.ToLower(msg.Get("kind").String()),
			ECS_RESOURCE_NAME: msg.Get("items.0.name").String(),
		},
		ECS_ORCHESTRATOR_TYPE: "kubernetes",
	}
}

// encodeOrchestrator creates an ECS orchestrator field.
func (ecs *ECSRecord) encodeOrchestrator(rec *engine.Record) {
	ecs.Orchestrator = JSONData{
		ECS_ORCHESTRATOR_NAMESPACE: engine.Mapper.MapStr(engine.SF_POD_NAMESPACE)(rec),
		ECS_ORCHESTRATOR_RESOURCE: JSONData{
			ECS_RESOURCE_TYPE: "pod",
			ECS_RESOURCE_NAME: engine.Mapper.MapStr(engine.SF_POD_NAME)(rec),
		},
		ECS_ORCHESTRATOR_TYPE: "kubernetes",
	}
}

// encodePod creates a custom ECS pod field.
func (ecs *ECSRecord) encodePod(rec *engine.Record) {
	ecs.Pod = JSONData{
		ECS_POD_TS:           utils.ToIsoTimeStr(engine.Mapper.MapInt(engine.SF_POD_TS)(rec)),
		ECS_POD_ID:           engine.Mapper.MapStr(engine.SF_POD_ID)(rec),
		ECS_POD_NAME:         engine.Mapper.MapStr(engine.SF_POD_NAME)(rec),
		ECS_POD_NODENAME:     engine.Mapper.MapStr(engine.SF_POD_NODENAME)(rec),
		ECS_POD_NAMESPACE:    engine.Mapper.MapStr(engine.SF_POD_NAMESPACE)(rec),
		ECS_POD_HOSTIP:       utils.ToIPStrArray(engine.Mapper.MapIntArray(engine.SF_POD_HOSTIP)(rec)),
		ECS_POD_INTERNALIP:   utils.ToIPStrArray(engine.Mapper.MapIntArray(engine.SF_POD_INTERNALIP)(rec)),
		ECS_POD_RESTARTCOUNT: engine.Mapper.MapInt(engine.SF_POD_RESTARTCOUNT)(rec),
	}

	services := engine.Mapper.MapSvcArray(engine.SF_POD_SERVICES)(rec)
	if services != sfgo.Zeros.Any && len(*services) > 0 {
		ecs.encodeService(services)
	}
}

// encodeServices creates an ECS service field.
func (ecs *ECSRecord) encodeService(svcs *[]*sfgo.Service) {
	ecs.Service = make([]JSONData, len(*svcs))
	for i, svc := range *svcs {
		ecs.Service[i] = JSONData{
			ECS_SERVICE_ID:        svc.Id,
			ECS_SERVICE_NAME:      svc.Name,
			ECS_SERVICE_NAMESPACE: svc.Namespace,
			ECS_SERVICE_CLUSTERIP: utils.ToIPStrArray(&svc.ClusterIP),
			ECS_SERVICE_PORTLIST:  encodePortList(&svc.PortList),
		}
	}
}

// encodePortList creates a ports field for an ECS service field.
func encodePortList(pl *[]*sfgo.Port) []JSONData {
	ports := make([]JSONData, len(*pl))
	for i, p := range *pl {
		ports[i] = JSONData{
			ECS_SERVICE_PORT:       p.Port,
			ECS_SERVICE_TARGETPORT: p.TargetPort,
			ECS_SERVICE_NODEPORT:   p.NodePort,
			ECS_SERVICE_PROTO:      p.Proto,
		}
	}
	return ports
}

// encodeContainer creates an ECS container field.
func encodeContainer(rec *engine.Record) JSONData {
	var container JSONData
	cid := engine.Mapper.MapStr(engine.SF_CONTAINER_ID)(rec)
	if cid != sfgo.Zeros.String {
		container = JSONData{
			ECS_CONTAINER_ID:      cid,
			ECS_CONTAINER_RUNTIME: engine.Mapper.MapStr(engine.SF_CONTAINER_TYPE)(rec),
			ECS_CONTAINER_PRIV:    engine.Mapper.MapInt(engine.SF_CONTAINER_PRIVILEGED)(rec) != 0,
			ECS_CONTAINER_NAME:    engine.Mapper.MapStr(engine.SF_CONTAINER_NAME)(rec),
			ECS_MOUNT_SOURCE:	   engine.Mapper.MapStr(engine.SF_CONTAINER_MOUNT_SOURCE)(rec),
			ECS_MOUNT_DEST:	   	   engine.Mapper.MapStr(engine.SF_CONTAINER_MOUNT_DEST)(rec),
			ECS_MOUNT_MODE:	   	   engine.Mapper.MapStr(engine.SF_CONTAINER_MOUNT_MODE)(rec),
			ECS_MOUNT_PROPAGATION: engine.Mapper.MapStr(engine.SF_CONTAINER_MOUNT_PROPAGATION)(rec),
		}
		imageid := engine.Mapper.MapStr(engine.SF_CONTAINER_IMAGEID)(rec)
		if imageid != sfgo.Zeros.String {
			image := JSONData{
				ECS_IMAGE_ID:   imageid,
				ECS_IMAGE_NAME: engine.Mapper.MapStr(engine.SF_CONTAINER_IMAGE)(rec),
				ECS_IMAGE_REPO: engine.Mapper.MapStr(engine.SF_CONTAINER_IMAGEREPO)(rec),
			}
			container[ECS_IMAGE] = image
		}
	}
	return container
}

// encodeHost creates the ECS host field
func encodeHost(rec *engine.Record) JSONData {
	return JSONData{
		ECS_HOST_ID: engine.Mapper.MapStr(engine.SF_NODE_ID)(rec),
		ECS_HOST_IP: engine.Mapper.MapStr(engine.SF_NODE_IP)(rec),
	}
}

// encodeHead creates the ECS host field
func encodeHead(rec *engine.Record) JSONData {
	return JSONData{
		ECS_HEAD_TS:	engine.Mapper.MapInt(engine.SF_TS)(rec),
		ECS_HEAD_ENDTS:	engine.Mapper.MapInt(engine.SF_ENDTS)(rec),
		ECS_HEAD_TYPE:	engine.Mapper.MapStr(engine.SF_TYPE)(rec),
	}
}

// encodePProcess creates an ECS parent process field.
func encodePProcess(rec *engine.Record) JSONData {
	pexe := engine.Mapper.MapStr(engine.SF_PPROC_EXE)(rec)
	pprocess := JSONData{
		ECS_PROC_EXE:     pexe,
		ECS_PROC_ARGS:    engine.Mapper.MapStr(engine.SF_PPROC_ARGS)(rec),
		ECS_PROC_CMDLINE: engine.Mapper.MapStr(engine.SF_PPROC_CMDLINE)(rec),
		ECS_PROC_START:   utils.ToIsoTimeStr(engine.Mapper.MapInt(engine.SF_PPROC_CREATETS)(rec)),
		ECS_PROC_NAME:    path.Base(pexe),
		ECS_PROC_TTY:	  engine.Mapper.MapInt(engine.SF_PPROC_TTY)(rec) != 0,
		ECS_PROC_OID:	  JSONData{
			ECS_PROC_HPID:		engine.Mapper.MapInt(engine.SF_PPROC_PID)(rec),
			ECS_PROC_CREATETS:	engine.Mapper.MapInt(engine.SF_PPROC_CREATETS)(rec),
		},
		ECS_PROC_UID:     engine.Mapper.MapInt(engine.SF_PPROC_UID)(rec),
		ECS_PROC_USER: 	  engine.Mapper.MapStr(engine.SF_PPROC_USER)(rec),
		ECS_PROC_GID:	  engine.Mapper.MapInt(engine.SF_PPROC_GID)(rec),
		ECS_PROC_GROUP:   engine.Mapper.MapStr(engine.SF_PPROC_GROUP)(rec),
	}
	return pprocess
}

// encodeProcess creates an ECS process field.
func encodeProcess(rec *engine.Record) JSONData {
	exe := engine.Mapper.MapStr(engine.SF_PROC_EXE)(rec)
	process := JSONData{
		ECS_PROC_EXE:     exe,
		ECS_PROC_ARGS:    engine.Mapper.MapStr(engine.SF_PROC_ARGS)(rec),
		ECS_PROC_CMDLINE: engine.Mapper.MapStr(engine.SF_PROC_CMDLINE)(rec),
		ECS_PROC_START:   utils.ToIsoTimeStr(engine.Mapper.MapInt(engine.SF_PROC_CREATETS)(rec)),
		ECS_PROC_NAME:    path.Base(exe),
		ECS_PROC_TID:     engine.Mapper.MapInt(engine.SF_PROC_TID)(rec),
		ECS_PROC_TTY:	  engine.Mapper.MapInt(engine.SF_PROC_TTY)(rec) != 0,
		ECS_PROC_OID:	  JSONData{
			ECS_PROC_HPID:		engine.Mapper.MapInt(engine.SF_PROC_PID)(rec),
			ECS_PROC_CREATETS:	engine.Mapper.MapInt(engine.SF_PROC_CREATETS)(rec),
		},
		ECS_PROC_UID:     engine.Mapper.MapInt(engine.SF_PROC_UID)(rec),
		ECS_PROC_USER: 	  engine.Mapper.MapStr(engine.SF_PROC_USER)(rec),
		ECS_PROC_GID:	  engine.Mapper.MapInt(engine.SF_PROC_GID)(rec),
		ECS_PROC_GROUP:   engine.Mapper.MapStr(engine.SF_PROC_GROUP)(rec),
		ECS_PROC_ANAME:	  engine.Mapper.MapStr(engine.SF_PROC_ANAME)(rec),
		ECS_PROC_OLDEXE:  engine.Mapper.MapStr(engine.SF_PROC_OLDEXE)(rec),
		ECS_PROC_OLDNAME: engine.Mapper.MapStr(engine.SF_PROC_OLDNAME)(rec),
	}
	return process
}

// encodeEvent creates the central ECS event field and sets the classification attributes
func encodeEvent(rec *engine.Record, category string, eventType string, action string) JSONData {
	start := engine.Mapper.MapInt(engine.SF_TS)(rec)
	end := engine.Mapper.MapInt(engine.SF_ENDTS)(rec)
	if end == sfgo.Zeros.Int64 {
		end = start
	}
	sfType := engine.Mapper.MapStr(engine.SF_TYPE)(rec)
	sfRet := engine.Mapper.MapInt(engine.SF_RET)(rec)
	opFlags := rec.GetInt(sfgo.EV_PROC_OPFLAGS_INT, sfgo.SYSFLOW_SRC)
	var ops string = ""
	if opFlags&sfgo.OP_CLONE == sfgo.OP_CLONE {
		ops = ops + "CLONE "
	} 
	if opFlags&sfgo.OP_EXEC == sfgo.OP_EXEC {
		ops = ops + "EXEC "
	} 
	if opFlags&sfgo.OP_EXIT == sfgo.OP_EXIT {
		ops = ops + "EXIT "
	} 
	if opFlags&sfgo.OP_SETUID == sfgo.OP_SETUID {
		ops = ops + "SETUID "
	} 
	if opFlags&sfgo.OP_SETNS == sfgo.OP_SETNS {
		ops = ops + "SETNS "
	} 
	if opFlags&sfgo.OP_ACCEPT == sfgo.OP_ACCEPT {
		ops = ops + "ACCEPT "
	} 
	if opFlags&sfgo.OP_READ_RECV == sfgo.OP_READ_RECV {
		ops = ops + "READ_RECV "
	} 
	if opFlags&sfgo.OP_WRITE_SEND == sfgo.OP_WRITE_SEND {
		ops = ops + "WRITE_SEND "
	} 
	if opFlags&sfgo.OP_CLOSE == sfgo.OP_CLOSE {
		ops = ops + "CLOSE "
	} 
	if opFlags&sfgo.OP_TRUNCATE == sfgo.OP_TRUNCATE {
		ops = ops + "TRUNCATE "
	} 
	if opFlags&sfgo.OP_SHUTDOWN == sfgo.OP_SHUTDOWN {
		ops = ops + "SHUTDOWN "
	} 
	if opFlags&sfgo.OP_MMAP == sfgo.OP_MMAP {
		ops = ops + "MMAP "
	} 
	if opFlags&sfgo.OP_DIGEST == sfgo.OP_DIGEST {
		ops = ops + "DIGEST "
	} 
	if opFlags&sfgo.OP_MKDIR == sfgo.OP_MKDIR {
		ops = ops + "MKDIR "
	} 
	if opFlags&sfgo.OP_RMDIR == sfgo.OP_MKDIR {
		ops = ops + "RMDIR "
	} 
	if opFlags&sfgo.OP_LINK == sfgo.OP_LINK {
		ops = ops + "LINK "
	} 
	if opFlags&sfgo.OP_UNLINK == sfgo.OP_UNLINK {
		ops = ops + "UNLINK "
	} 
	if opFlags&sfgo.OP_SYMLINK == sfgo.OP_SYMLINK {
		ops = ops + "SYMLINK "
	} 
	if opFlags&sfgo.OP_RENAME == sfgo.OP_RENAME {
		ops = ops + "RENAME "
	} 

	event := JSONData{
		ECS_EVENT_CATEGORY: 	category,
		ECS_EVENT_TYPE:     	eventType,
		ECS_EVENT_ACTION:   	action,
		ECS_EVENT_SFTYPE:   	sfType,
		ECS_EVENT_START:    	utils.ToIsoTimeStr(start),
		ECS_EVENT_END:      	utils.ToIsoTimeStr(end),
		ECS_EVENT_DURATION:  	end - start,
		ECS_EVENT_OPFLAGSINT:	opFlags,
		ECS_EVENT_OPFLAGS:		ops,
	}

	if rec.Ctx.IsAlert() {
		event[ECS_EVENT_KIND] = ECS_KIND_ALERT
	} else {
		event[ECS_EVENT_KIND] = ECS_KIND_EVENT
	}

	if sfType == sfgo.TyPEStr || sfType == sfgo.TyFEStr {
		event[ECS_EVENT_SFRET] = sfRet
	}
	return event
}

// encodeFile creates an ECS file field
func encodeFile(rec *engine.Record) JSONData {
	opFlags := rec.GetInt(sfgo.EV_PROC_OPFLAGS_INT, sfgo.SYSFLOW_SRC)
	ft := engine.Mapper.MapStr(engine.SF_FILE_TYPE)(rec)
	ft_char := engine.Mapper.MapInt(engine.SF_FILE_TYPE)(rec)
	fpath := engine.Mapper.MapStr(engine.SF_FILE_PATH)(rec)
	fd := engine.Mapper.MapInt(engine.SF_FILE_FD)(rec)
	pid := engine.Mapper.MapInt(engine.SF_PROC_PID)(rec)
	oid := engine.Mapper.MapStr(engine.SF_FILE_OID)(rec)
	newoid := engine.Mapper.MapStr(engine.SF_FILE_NEWOID)(rec)
	newpath := engine.Mapper.MapStr(engine.SF_FILE_NEWPATH)(rec)
	is_open_read := engine.Mapper.MapInt(engine.SF_FILE_IS_OPEN_READ)(rec) != 0
	is_open_write := engine.Mapper.MapInt(engine.SF_FILE_IS_OPEN_WRITE)(rec) != 0
	openflags_int := engine.Mapper.MapInt(engine.SF_FILE_OPENFLAGS)(rec)
	var opens string = ""
	if openflags_int == sfgo.O_NONE {
		opens = "O_NONE "
	} else {
		if openflags_int&sfgo.O_RDWR == sfgo.O_RDWR {
			opens = "O_WRONLY "
		} else if openflags_int&sfgo.O_RDONLY == sfgo.O_RDONLY {
			opens = "O_RDONLY "
		} else if openflags_int&sfgo.O_WRONLY == sfgo.O_WRONLY {
			opens = "O_WRONLY "
		}
		if openflags_int&sfgo.O_CREAT == sfgo.O_CREAT {
			opens = opens + "O_CREAT "
		}
		if openflags_int&sfgo.O_APPEND == sfgo.O_APPEND {
			opens = opens + "O_CREAT "
		}
		if openflags_int&sfgo.O_CREAT == sfgo.O_CREAT {
			opens = opens + "O_APPEND "
		}
		if openflags_int&sfgo.O_DSYNC == sfgo.O_DSYNC {
			opens = opens + "O_DSYNC "
		}
		if openflags_int&sfgo.O_EXCL == sfgo.O_EXCL {
			opens = opens + "O_EXCL "
		}
		if openflags_int&sfgo.O_NONBLOCK == sfgo.O_NONBLOCK {
			opens = opens + "O_NONBLOCK "
		}
		if openflags_int&sfgo.O_SYNC == sfgo.O_SYNC {
			opens = opens + "O_SYNC "
		}
		if openflags_int&sfgo.O_TRUNC == sfgo.O_TRUNC {
			opens = opens + "O_TRUNC "
		}
		if openflags_int&sfgo.O_DIRECT == sfgo.O_DIRECT {
			opens = opens + "O_DIRECT "
		}
		if openflags_int&sfgo.O_DIRECTORY == sfgo.O_DIRECTORY {
			opens = opens + "O_DIRECTORY "
		}
		if openflags_int&sfgo.O_LARGEFILE == sfgo.O_LARGEFILE {
			opens = opens + "O_LARGEFILE "
		}
		if openflags_int&sfgo.O_CLOEXEC == sfgo.O_CLOEXEC {
			opens = opens + "O_CLOEXEC "
		}
	}

	fileType := encodeFileType(ft)
	if opFlags&sfgo.OP_SYMLINK == sfgo.OP_SYMLINK {
		fileType = "symlink"
	}
	file := JSONData{ECS_FILE_TYPE: fileType,
					 ECS_FILE_OID: oid,
					 ECS_FILE_NEW_OID: newoid,
					 ECS_FILE_NEWPATH: newpath,
					 ECS_FILE_OPENFLAGS_INT: openflags_int,
					 ECS_FILE_OPENFLAGS: opens,
					 ECS_FILE_IS_OPEN_READ: is_open_read,
					 ECS_FILE_IS_OPEN_WRITE: is_open_write,
					 ECS_FILE_TYPECHAR: ft_char,
	}

	var name string
	if fpath != sfgo.Zeros.String {
		name = path.Base(fpath)
	} else {
		fpath = fmt.Sprintf("/proc/%d/fd/%d", pid, fd)
		name = strconv.FormatInt(fd, 10)
	}

	if fileType == "dir" {
		file[ECS_FILE_DIR] = fpath
	} else {
		file[ECS_FILE_NAME] = name
		file[ECS_FILE_DIR] = filepath.Dir(fpath)
		if fpath != name {
			file[ECS_FILE_PATH] = fpath
		}
	}

	return file
}

func encodeFileType(ft string) string {
	var fileType string
	switch ft {
	case "f":
		fileType = "file"
	case "d":
		fileType = "dir"
	case "u":
		fileType = "socket"
	case "p":
		fileType = "pipe"
	case "?":
		fallthrough
	default:
		fileType = "unknown"
	}
	return fileType
}

func extracTags(tags []engine.EnrichmentTag) []string {
	s := make([]string, 0)
	for _, v := range tags {
		switch v := v.(type) {
		case []string:
			s = append(s, v...)
		default:
			s = append(s, string(fmt.Sprintf("%v", v)))
		}
	}
	return s
}

// Cleanup cleans up resources.
func (t *ECSEncoder) Cleanup() {}
