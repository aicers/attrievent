use std::str::FromStr;

use anyhow::{Result, anyhow};
use review_protocol::types::RawEventKind;
use strum_macros::{Display, EnumIter, EnumString};

/// An attribute of a raw event, one variant per [`RawEventKind`] holding
/// that kind's attribute enum.
#[derive(Debug, PartialEq)]
pub enum RawEventAttrKind {
    Conn(ConnAttr),
    Dns(DnsAttr),
    Http(HttpAttr),
    Rdp(RdpAttr),
    Smtp(SmtpAttr),
    Ntlm(NtlmAttr),
    Kerberos(KerberosAttr),
    Ssh(SshAttr),
    DceRpc(DceRpcAttr),
    Ftp(FtpAttr),
    Mqtt(MqttAttr),
    Ldap(LdapAttr),
    Tls(TlsAttr),
    Smb(SmbAttr),
    Nfs(NfsAttr),
    Bootp(BootpAttr),
    Dhcp(DhcpAttr),
    Radius(RadiusAttr),
    MalformedDns(MalformedDnsAttr),
    Icmp(IcmpAttr),
    ProcessCreate(ProcessCreateAttr),
    FileCreateTime(FileCreateTimeAttr),
    NetworkConnect(NetworkConnectAttr),
    ProcessTerminate(ProcessTerminateAttr),
    DriverLoad(DriverLoadAttr),
    ImageLoad(ImageLoadAttr),
    CreateRemoteThread(CreateRemoteThreadAttr),
    RawAccessRead(RawAccessReadAttr),
    ProcessAccess(ProcessAccessAttr),
    FileCreate(FileCreateAttr),
    RegistryObjectAddDel(RegistryObjectAddDelAttr),
    RegistryValueSet(RegistryValueSetAttr),
    RegistryKeyRename(RegistryKeyRenameAttr),
    FileCreateStreamHash(FileCreateStreamHashAttr),
    PipeEvent(PipeEventAttr),
    DnsQuery(DnsQueryAttr),
    FileDelete(FileDeleteAttr),
    ProcessTamper(ProcessTamperAttr),
    FileDeleteDetected(FileDeleteDetectedAttr),
    Netflow5(Netflow5Attr),
    Netflow9(Netflow9Attr),
    WindowsEventLog(WindowsEventLogAttr),
    Journald(JournaldAttr),
    Auditd(AuditdAttr),
}

impl RawEventAttrKind {
    /// Creates a new `RawEventAttrKind` from a raw event kind and the display
    /// name of one of that kind's attributes.
    ///
    /// # Errors
    ///
    /// Returns an error if `attr_name` is not the display name of any
    /// attribute of `raw_event_kind`.
    pub fn from_kind_and_attr_name(
        raw_event_kind: &RawEventKind,
        attr_name: &str,
    ) -> Result<RawEventAttrKind> {
        macro_rules! handle_attr {
            ($attr:ident, $type:ident) => {
                $attr::from_str(attr_name).map(RawEventAttrKind::$type)
            };
        }

        // One arm per kind and no wildcard, so that a kind added to
        // review-protocol fails to compile here until its attribute enum
        // exists.
        let parse_result = match raw_event_kind {
            RawEventKind::Conn => handle_attr!(ConnAttr, Conn),
            RawEventKind::Dns => handle_attr!(DnsAttr, Dns),
            RawEventKind::Http => handle_attr!(HttpAttr, Http),
            RawEventKind::Rdp => handle_attr!(RdpAttr, Rdp),
            RawEventKind::Smtp => handle_attr!(SmtpAttr, Smtp),
            RawEventKind::Ntlm => handle_attr!(NtlmAttr, Ntlm),
            RawEventKind::Kerberos => handle_attr!(KerberosAttr, Kerberos),
            RawEventKind::Ssh => handle_attr!(SshAttr, Ssh),
            RawEventKind::DceRpc => handle_attr!(DceRpcAttr, DceRpc),
            RawEventKind::Ftp => handle_attr!(FtpAttr, Ftp),
            RawEventKind::Mqtt => handle_attr!(MqttAttr, Mqtt),
            RawEventKind::Ldap => handle_attr!(LdapAttr, Ldap),
            RawEventKind::Tls => handle_attr!(TlsAttr, Tls),
            RawEventKind::Smb => handle_attr!(SmbAttr, Smb),
            RawEventKind::Nfs => handle_attr!(NfsAttr, Nfs),
            RawEventKind::Bootp => handle_attr!(BootpAttr, Bootp),
            RawEventKind::Dhcp => handle_attr!(DhcpAttr, Dhcp),
            RawEventKind::Radius => handle_attr!(RadiusAttr, Radius),
            RawEventKind::MalformedDns => handle_attr!(MalformedDnsAttr, MalformedDns),
            RawEventKind::Icmp => handle_attr!(IcmpAttr, Icmp),
            RawEventKind::ProcessCreate => handle_attr!(ProcessCreateAttr, ProcessCreate),
            RawEventKind::FileCreateTime => handle_attr!(FileCreateTimeAttr, FileCreateTime),
            RawEventKind::NetworkConnect => handle_attr!(NetworkConnectAttr, NetworkConnect),
            RawEventKind::ProcessTerminate => {
                handle_attr!(ProcessTerminateAttr, ProcessTerminate)
            }
            RawEventKind::DriverLoad => handle_attr!(DriverLoadAttr, DriverLoad),
            RawEventKind::ImageLoad => handle_attr!(ImageLoadAttr, ImageLoad),
            RawEventKind::CreateRemoteThread => {
                handle_attr!(CreateRemoteThreadAttr, CreateRemoteThread)
            }
            RawEventKind::RawAccessRead => handle_attr!(RawAccessReadAttr, RawAccessRead),
            RawEventKind::ProcessAccess => handle_attr!(ProcessAccessAttr, ProcessAccess),
            RawEventKind::FileCreate => handle_attr!(FileCreateAttr, FileCreate),
            RawEventKind::RegistryObjectAddDel => {
                handle_attr!(RegistryObjectAddDelAttr, RegistryObjectAddDel)
            }
            RawEventKind::RegistryValueSet => {
                handle_attr!(RegistryValueSetAttr, RegistryValueSet)
            }
            RawEventKind::RegistryKeyRename => {
                handle_attr!(RegistryKeyRenameAttr, RegistryKeyRename)
            }
            RawEventKind::FileCreateStreamHash => {
                handle_attr!(FileCreateStreamHashAttr, FileCreateStreamHash)
            }
            RawEventKind::PipeEvent => handle_attr!(PipeEventAttr, PipeEvent),
            RawEventKind::DnsQuery => handle_attr!(DnsQueryAttr, DnsQuery),
            RawEventKind::FileDelete => handle_attr!(FileDeleteAttr, FileDelete),
            RawEventKind::ProcessTamper => handle_attr!(ProcessTamperAttr, ProcessTamper),
            RawEventKind::FileDeleteDetected => {
                handle_attr!(FileDeleteDetectedAttr, FileDeleteDetected)
            }
            RawEventKind::Netflow5 => handle_attr!(Netflow5Attr, Netflow5),
            RawEventKind::Netflow9 => handle_attr!(Netflow9Attr, Netflow9),
            RawEventKind::WindowsEventLog => handle_attr!(WindowsEventLogAttr, WindowsEventLog),
            RawEventKind::Journald => handle_attr!(JournaldAttr, Journald),
            RawEventKind::Auditd => handle_attr!(AuditdAttr, Auditd),
        };
        parse_result.map_err(|e| anyhow!("Unknown attribute name: {e}"))
    }
}

#[derive(Debug, EnumString, PartialEq, EnumIter, Display)]
pub enum BootpAttr {
    #[strum(serialize = "Source IP")]
    SrcAddr,
    #[strum(serialize = "Source Port")]
    SrcPort,
    #[strum(serialize = "Destination IP")]
    DstAddr,
    #[strum(serialize = "Destination Port")]
    DstPort,
    #[strum(serialize = "Protocol Number")]
    Proto,
    #[strum(serialize = "Duration")]
    Duration,
    #[strum(serialize = "Packets Sent")]
    OrigPkts,
    #[strum(serialize = "Packets Received")]
    RespPkts,
    #[strum(serialize = "Layer 2 Bytes Sent")]
    OrigL2Bytes,
    #[strum(serialize = "Layer 2 Bytes Received")]
    RespL2Bytes,
    #[strum(serialize = "Operation Code")]
    Op,
    #[strum(serialize = "Hardware Type")]
    Htype,
    #[strum(serialize = "Hop Count")]
    Hops,
    #[strum(serialize = "Transaction ID")]
    Xid,
    #[strum(serialize = "Client IP")]
    CiAddr,
    #[strum(serialize = "Your IP")]
    YiAddr,
    #[strum(serialize = "Server IP")]
    SiAddr,
    #[strum(serialize = "Gateway IP")]
    GiAddr,
    #[strum(serialize = "Client Hardware IP")]
    ChAddr,
    #[strum(serialize = "Server Hostname")]
    SName,
    #[strum(serialize = "Boot Filename")]
    File,
}

#[derive(Debug, EnumString, PartialEq, EnumIter, Display)]
pub enum ConnAttr {
    #[strum(serialize = "Source IP")]
    SrcAddr,
    #[strum(serialize = "Source Port")]
    SrcPort,
    #[strum(serialize = "Destination IP")]
    DstAddr,
    #[strum(serialize = "Destination Port")]
    DstPort,
    #[strum(serialize = "Protocol Number")]
    Proto,
    #[strum(serialize = "Connection State")]
    ConnState,
    #[strum(serialize = "Duration")]
    Duration,
    #[strum(serialize = "Service Name")]
    Service,
    #[strum(serialize = "Bytes Sent")]
    OrigBytes,
    #[strum(serialize = "Bytes Received")]
    RespBytes,
    #[strum(serialize = "Packets Sent")]
    OrigPkts,
    #[strum(serialize = "Packets Received")]
    RespPkts,
    #[strum(serialize = "Layer 2 Bytes Sent")]
    OrigL2Bytes,
    #[strum(serialize = "Layer 2 Bytes Received")]
    RespL2Bytes,
}

#[derive(Debug, EnumString, PartialEq, EnumIter, Display)]
pub enum DhcpAttr {
    #[strum(serialize = "Source IP")]
    SrcAddr,
    #[strum(serialize = "Source Port")]
    SrcPort,
    #[strum(serialize = "Destination IP")]
    DstAddr,
    #[strum(serialize = "Destination Port")]
    DstPort,
    #[strum(serialize = "Protocol Number")]
    Proto,
    #[strum(serialize = "Duration")]
    Duration,
    #[strum(serialize = "Packets Sent")]
    OrigPkts,
    #[strum(serialize = "Packets Received")]
    RespPkts,
    #[strum(serialize = "Layer 2 Bytes Sent")]
    OrigL2Bytes,
    #[strum(serialize = "Layer 2 Bytes Received")]
    RespL2Bytes,
    #[strum(serialize = "Message Type")]
    MsgType,
    #[strum(serialize = "Client IP")]
    CiAddr,
    #[strum(serialize = "Your IP")]
    YiAddr,
    #[strum(serialize = "Server IP")]
    SiAddr,
    #[strum(serialize = "Gateway IP")]
    GiAddr,
    #[strum(serialize = "Subnet Mask")]
    SubNetMask,
    #[strum(serialize = "Routers")]
    Router,
    #[strum(serialize = "Domain Name Servers")]
    DomainNameServer,
    #[strum(serialize = "Request IP")]
    ReqIpAddr,
    #[strum(serialize = "Lease Time")]
    LeaseTime,
    #[strum(serialize = "Server ID")]
    ServerId,
    #[strum(serialize = "Parameter Request List")]
    ParamReqList,
    #[strum(serialize = "Message")]
    Message,
    #[strum(serialize = "Renewal Time")]
    RenewalTime,
    #[strum(serialize = "Rebinding Time")]
    RebindingTime,
    #[strum(serialize = "Class ID List")]
    ClassId,
    #[strum(serialize = "Client ID Type")]
    ClientIdType,
    #[strum(serialize = "Client ID List")]
    ClientId,
    #[strum(serialize = "Option Code")]
    OptionCode,
    #[strum(serialize = "Option Data")]
    OptionData,
}

#[derive(Debug, EnumString, PartialEq, EnumIter, Display)]
pub enum DceRpcAttr {
    #[strum(serialize = "Source IP")]
    SrcAddr,
    #[strum(serialize = "Source Port")]
    SrcPort,
    #[strum(serialize = "Destination IP")]
    DstAddr,
    #[strum(serialize = "Destination Port")]
    DstPort,
    #[strum(serialize = "Protocol Number")]
    Proto,
    #[strum(serialize = "Duration")]
    Duration,
    #[strum(serialize = "Packets Sent")]
    OrigPkts,
    #[strum(serialize = "Packets Received")]
    RespPkts,
    #[strum(serialize = "Layer 2 Bytes Sent")]
    OrigL2Bytes,
    #[strum(serialize = "Layer 2 Bytes Received")]
    RespL2Bytes,
    #[strum(serialize = "Presentation Context ID")]
    ContextId,
    #[strum(serialize = "Abstract Syntax UUID")]
    AbstractSyntax,
    #[strum(serialize = "Abstract Syntax Major Version")]
    AbstractMajor,
    #[strum(serialize = "Abstract Syntax Minor Version")]
    AbstractMinor,
    #[strum(serialize = "Transfer Syntax UUID")]
    TransferSyntax,
    #[strum(serialize = "Transfer Syntax Major Version")]
    TransferMajor,
    #[strum(serialize = "Transfer Syntax Minor Version")]
    TransferMinor,
    #[strum(serialize = "Presentation Context Result")]
    Acceptance,
    #[strum(serialize = "Provider Rejection Reason")]
    Reason,
    #[strum(serialize = "Request Context ID")]
    RequestContextId,
    #[strum(serialize = "Request Operation Number")]
    RequestOpnum,
}

#[derive(Debug, EnumString, PartialEq, EnumIter, Display)]
pub enum DnsAttr {
    #[strum(serialize = "Source IP")]
    SrcAddr,
    #[strum(serialize = "Source Port")]
    SrcPort,
    #[strum(serialize = "Destination IP")]
    DstAddr,
    #[strum(serialize = "Destination Port")]
    DstPort,
    #[strum(serialize = "Protocol Number")]
    Proto,
    #[strum(serialize = "Duration")]
    Duration,
    #[strum(serialize = "Packets Sent")]
    OrigPkts,
    #[strum(serialize = "Packets Received")]
    RespPkts,
    #[strum(serialize = "Layer 2 Bytes Sent")]
    OrigL2Bytes,
    #[strum(serialize = "Layer 2 Bytes Received")]
    RespL2Bytes,
    #[strum(serialize = "Query")]
    Query,
    #[strum(serialize = "Answer")]
    Answer,
    #[strum(serialize = "Transaction ID")]
    TransId,
    #[strum(serialize = "Round-Trip Time")]
    Rtt,
    #[strum(serialize = "Query Class")]
    QClass,
    #[strum(serialize = "Query Type")]
    QType,
    #[strum(serialize = "Response Code")]
    RCode,
    #[strum(serialize = "Authoritative Answer Flag")]
    AA,
    #[strum(serialize = "Truncation Flag")]
    TC,
    #[strum(serialize = "Recursion Desired Flag")]
    RD,
    #[strum(serialize = "Recursion Available Flag")]
    RA,
    #[strum(serialize = "Time to live")]
    Ttl,
}

#[derive(Debug, EnumString, PartialEq, EnumIter, Display)]
pub enum FtpAttr {
    #[strum(serialize = "Source IP")]
    SrcAddr,
    #[strum(serialize = "Source Port")]
    SrcPort,
    #[strum(serialize = "Destination IP")]
    DstAddr,
    #[strum(serialize = "Destination Port")]
    DstPort,
    #[strum(serialize = "Protocol Number")]
    Proto,
    #[strum(serialize = "Duration")]
    Duration,
    #[strum(serialize = "Packets Sent")]
    OrigPkts,
    #[strum(serialize = "Packets Received")]
    RespPkts,
    #[strum(serialize = "Layer 2 Bytes Sent")]
    OrigL2Bytes,
    #[strum(serialize = "Layer 2 Bytes Received")]
    RespL2Bytes,
    #[strum(serialize = "Username")]
    User,
    #[strum(serialize = "Password")]
    Password,
    #[strum(serialize = "Command")]
    Command,
    #[strum(serialize = "Reply Code")]
    ReplyCode,
    #[strum(serialize = "Reply Message")]
    ReplyMsg,
    #[strum(serialize = "Passive Mode Flag")]
    DataPassive,
    #[strum(serialize = "Data Channel Source IP")]
    DataOrigAddr,
    #[strum(serialize = "Data Channel Destination IP")]
    DataRespAddr,
    #[strum(serialize = "Data Channel Destination Port")]
    DataRespPort,
    #[strum(serialize = "Filename")]
    File,
    #[strum(serialize = "File Size")]
    FileSize,
    #[strum(serialize = "File ID")]
    FileId,
}

#[derive(Debug, EnumString, PartialEq, EnumIter, Display)]
pub enum HttpAttr {
    #[strum(serialize = "Source IP")]
    SrcAddr,
    #[strum(serialize = "Source Port")]
    SrcPort,
    #[strum(serialize = "Destination IP")]
    DstAddr,
    #[strum(serialize = "Destination Port")]
    DstPort,
    #[strum(serialize = "Protocol Number")]
    Proto,
    #[strum(serialize = "Duration")]
    Duration,
    #[strum(serialize = "Packets Sent")]
    OrigPkts,
    #[strum(serialize = "Packets Received")]
    RespPkts,
    #[strum(serialize = "Layer 2 Bytes Sent")]
    OrigL2Bytes,
    #[strum(serialize = "Layer 2 Bytes Received")]
    RespL2Bytes,
    #[strum(serialize = "HTTP Method")]
    Method,
    #[strum(serialize = "Host")]
    Host,
    #[strum(serialize = "URI")]
    Uri,
    #[strum(serialize = "Referer")]
    Referer,
    #[strum(serialize = "HTTP Version")]
    Version,
    #[strum(serialize = "User Agent")]
    UserAgent,
    #[strum(serialize = "Request Length")]
    RequestLen,
    #[strum(serialize = "Response Length")]
    ResponseLen,
    #[strum(serialize = "Status Code")]
    StatusCode,
    #[strum(serialize = "Status Message")]
    StatusMsg,
    #[strum(serialize = "Username")]
    Username,
    #[strum(serialize = "Password")]
    Password,
    #[strum(serialize = "Cookie")]
    Cookie,
    #[strum(serialize = "Content Encoding")]
    ContentEncoding,
    #[strum(serialize = "Content Type")]
    ContentType,
    #[strum(serialize = "Cache Control")]
    CacheControl,
    #[strum(serialize = "Filenames")]
    Filenames,
    #[strum(serialize = "MIME Types")]
    MimeTypes,
    #[strum(serialize = "Body")]
    Body,
    #[strum(serialize = "Last State")]
    State,
}

#[derive(Debug, EnumString, PartialEq, EnumIter, Display)]
pub enum KerberosAttr {
    #[strum(serialize = "Source IP")]
    SrcAddr,
    #[strum(serialize = "Source Port")]
    SrcPort,
    #[strum(serialize = "Destination IP")]
    DstAddr,
    #[strum(serialize = "Destination Port")]
    DstPort,
    #[strum(serialize = "Protocol Number")]
    Proto,
    #[strum(serialize = "Duration")]
    Duration,
    #[strum(serialize = "Packets Sent")]
    OrigPkts,
    #[strum(serialize = "Packets Received")]
    RespPkts,
    #[strum(serialize = "Layer 2 Bytes Sent")]
    OrigL2Bytes,
    #[strum(serialize = "Layer 2 Bytes Received")]
    RespL2Bytes,
    #[strum(serialize = "Client Time")]
    ClientTime,
    #[strum(serialize = "Server Time")]
    ServerTime,
    #[strum(serialize = "Error Code")]
    ErrorCode,
    #[strum(serialize = "Client Realm")]
    ClientRealm,
    #[strum(serialize = "Client Name Type")]
    CnameType,
    #[strum(serialize = "Client Name")]
    ClientName,
    #[strum(serialize = "Realm")]
    Realm,
    #[strum(serialize = "Service Name Type")]
    SnameType,
    #[strum(serialize = "Service Name")]
    ServiceName,
}

#[derive(Debug, EnumString, PartialEq, EnumIter, Display)]
pub enum LdapAttr {
    #[strum(serialize = "Source IP")]
    SrcAddr,
    #[strum(serialize = "Source Port")]
    SrcPort,
    #[strum(serialize = "Destination IP")]
    DstAddr,
    #[strum(serialize = "Destination Port")]
    DstPort,
    #[strum(serialize = "Protocol Number")]
    Proto,
    #[strum(serialize = "Duration")]
    Duration,
    #[strum(serialize = "Packets Sent")]
    OrigPkts,
    #[strum(serialize = "Packets Received")]
    RespPkts,
    #[strum(serialize = "Layer 2 Bytes Sent")]
    OrigL2Bytes,
    #[strum(serialize = "Layer 2 Bytes Received")]
    RespL2Bytes,
    #[strum(serialize = "Message ID")]
    MessageId,
    #[strum(serialize = "Version")]
    Version,
    #[strum(serialize = "Operation Code")]
    Opcode,
    #[strum(serialize = "Result Code")]
    Result,
    #[strum(serialize = "Diagnostic Message")]
    DiagnosticMessage,
    #[strum(serialize = "Object")]
    Object,
    #[strum(serialize = "Argument")]
    Argument,
}

#[derive(Debug, EnumString, PartialEq, EnumIter, Display)]
pub enum MqttAttr {
    #[strum(serialize = "Source IP")]
    SrcAddr,
    #[strum(serialize = "Source Port")]
    SrcPort,
    #[strum(serialize = "Destination IP")]
    DstAddr,
    #[strum(serialize = "Destination Port")]
    DstPort,
    #[strum(serialize = "Protocol Number")]
    Proto,
    #[strum(serialize = "Duration")]
    Duration,
    #[strum(serialize = "Packets Sent")]
    OrigPkts,
    #[strum(serialize = "Packets Received")]
    RespPkts,
    #[strum(serialize = "Layer 2 Bytes Sent")]
    OrigL2Bytes,
    #[strum(serialize = "Layer 2 Bytes Received")]
    RespL2Bytes,
    #[strum(serialize = "MQTT Protocol")]
    Protocol,
    #[strum(serialize = "Version")]
    Version,
    #[strum(serialize = "Client ID")]
    ClientId,
    #[strum(serialize = "Connection Acknowledgement Response")]
    ConnackReason,
    #[strum(serialize = "Subscription Request")]
    Subscribe,
    #[strum(serialize = "Subscription Acknowledgement Response")]
    SubackReason,
}

#[derive(Debug, EnumString, PartialEq, EnumIter, Display)]
pub enum NfsAttr {
    #[strum(serialize = "Source IP")]
    SrcAddr,
    #[strum(serialize = "Source Port")]
    SrcPort,
    #[strum(serialize = "Destination IP")]
    DstAddr,
    #[strum(serialize = "Destination Port")]
    DstPort,
    #[strum(serialize = "Protocol Number")]
    Proto,
    #[strum(serialize = "Duration")]
    Duration,
    #[strum(serialize = "Packets Sent")]
    OrigPkts,
    #[strum(serialize = "Packets Received")]
    RespPkts,
    #[strum(serialize = "Layer 2 Bytes Sent")]
    OrigL2Bytes,
    #[strum(serialize = "Layer 2 Bytes Received")]
    RespL2Bytes,
    #[strum(serialize = "Read Files")]
    ReadFiles,
    #[strum(serialize = "Write Files")]
    WriteFiles,
}

#[derive(Debug, EnumString, PartialEq, EnumIter, Display)]
pub enum NtlmAttr {
    #[strum(serialize = "Source IP")]
    SrcAddr,
    #[strum(serialize = "Source Port")]
    SrcPort,
    #[strum(serialize = "Destination IP")]
    DstAddr,
    #[strum(serialize = "Destination Port")]
    DstPort,
    #[strum(serialize = "Protocol Number")]
    Proto,
    #[strum(serialize = "Duration")]
    Duration,
    #[strum(serialize = "Packets Sent")]
    OrigPkts,
    #[strum(serialize = "Packets Received")]
    RespPkts,
    #[strum(serialize = "Layer 2 Bytes Sent")]
    OrigL2Bytes,
    #[strum(serialize = "Layer 2 Bytes Received")]
    RespL2Bytes,
    #[strum(serialize = "NTLM Protocol")]
    Protocol,
    #[strum(serialize = "Username")]
    Username,
    #[strum(serialize = "Hostname")]
    Hostname,
    #[strum(serialize = "Domain Name")]
    Domainname,
    #[strum(serialize = "Success Flag")]
    Success,
}

#[derive(Debug, EnumString, PartialEq, EnumIter, Display)]
pub enum RadiusAttr {
    #[strum(serialize = "Source IP")]
    SrcAddr,
    #[strum(serialize = "Source Port")]
    SrcPort,
    #[strum(serialize = "Destination IP")]
    DstAddr,
    #[strum(serialize = "Destination Port")]
    DstPort,
    #[strum(serialize = "Protocol Number")]
    Proto,
    #[strum(serialize = "Duration")]
    Duration,
    #[strum(serialize = "Packets Sent")]
    OrigPkts,
    #[strum(serialize = "Packets Received")]
    RespPkts,
    #[strum(serialize = "Layer 2 Bytes Sent")]
    OrigL2Bytes,
    #[strum(serialize = "Layer 2 Bytes Received")]
    RespL2Bytes,
    #[strum(serialize = "ID")]
    Id,
    #[strum(serialize = "Request Code")]
    Code,
    #[strum(serialize = "Response Code")]
    RespCode,
    #[strum(serialize = "Request Authenticator")]
    Auth,
    #[strum(serialize = "Response Authenticator")]
    RespAuth,
    #[strum(serialize = "Username")]
    UserName,
    #[strum(serialize = "Password")]
    UserPasswd,
    #[strum(serialize = "CHAP Response")]
    ChapPasswd,
    #[strum(serialize = "NAS IP")]
    NasIp,
    #[strum(serialize = "NAS Port")]
    NasPort,
    #[strum(serialize = "State")]
    State,
    #[strum(serialize = "NAS ID")]
    NasId,
    #[strum(serialize = "NAS Port Type")]
    NasPortType,
    #[strum(serialize = "Message")]
    Message,
}

#[derive(Debug, EnumString, PartialEq, EnumIter, Display)]
pub enum RdpAttr {
    #[strum(serialize = "Source IP")]
    SrcAddr,
    #[strum(serialize = "Source Port")]
    SrcPort,
    #[strum(serialize = "Destination IP")]
    DstAddr,
    #[strum(serialize = "Destination Port")]
    DstPort,
    #[strum(serialize = "Protocol Number")]
    Proto,
    #[strum(serialize = "Duration")]
    Duration,
    #[strum(serialize = "Packets Sent")]
    OrigPkts,
    #[strum(serialize = "Packets Received")]
    RespPkts,
    #[strum(serialize = "Layer 2 Bytes Sent")]
    OrigL2Bytes,
    #[strum(serialize = "Layer 2 Bytes Received")]
    RespL2Bytes,
    #[strum(serialize = "Cookie")]
    Cookie,
}

#[derive(Debug, EnumString, PartialEq, EnumIter, Display)]
pub enum SmbAttr {
    #[strum(serialize = "Source IP")]
    SrcAddr,
    #[strum(serialize = "Source Port")]
    SrcPort,
    #[strum(serialize = "Destination IP")]
    DstAddr,
    #[strum(serialize = "Destination Port")]
    DstPort,
    #[strum(serialize = "Protocol Number")]
    Proto,
    #[strum(serialize = "Duration")]
    Duration,
    #[strum(serialize = "Packets Sent")]
    OrigPkts,
    #[strum(serialize = "Packets Received")]
    RespPkts,
    #[strum(serialize = "Layer 2 Bytes Sent")]
    OrigL2Bytes,
    #[strum(serialize = "Layer 2 Bytes Received")]
    RespL2Bytes,
    #[strum(serialize = "Command")]
    Command,
    #[strum(serialize = "Path")]
    Path,
    #[strum(serialize = "Service")]
    Service,
    #[strum(serialize = "Filename")]
    FileName,
    #[strum(serialize = "File Size")]
    FileSize,
    #[strum(serialize = "Resource Type")]
    ResourceType,
    #[strum(serialize = "File ID")]
    Fid,
    #[strum(serialize = "Create Time")]
    CreateTime,
    #[strum(serialize = "Access Time")]
    AccessTime,
    #[strum(serialize = "Write Time")]
    WriteTime,
    #[strum(serialize = "Change Time")]
    ChangeTime,
}

#[derive(Debug, EnumString, PartialEq, EnumIter, Display)]
pub enum SmtpAttr {
    #[strum(serialize = "Source IP")]
    SrcAddr,
    #[strum(serialize = "Source Port")]
    SrcPort,
    #[strum(serialize = "Destination IP")]
    DstAddr,
    #[strum(serialize = "Destination Port")]
    DstPort,
    #[strum(serialize = "Protocol Number")]
    Proto,
    #[strum(serialize = "Duration")]
    Duration,
    #[strum(serialize = "Packets Sent")]
    OrigPkts,
    #[strum(serialize = "Packets Received")]
    RespPkts,
    #[strum(serialize = "Layer 2 Bytes Sent")]
    OrigL2Bytes,
    #[strum(serialize = "Layer 2 Bytes Received")]
    RespL2Bytes,
    #[strum(serialize = "Mail From")]
    MailFrom,
    #[strum(serialize = "Date")]
    Date,
    #[strum(serialize = "From")]
    From,
    #[strum(serialize = "To")]
    To,
    #[strum(serialize = "Subject")]
    Subject,
    #[strum(serialize = "Agent")]
    Agent,
    #[strum(serialize = "States")]
    State,
}

#[derive(Debug, EnumString, PartialEq, EnumIter, Display)]
pub enum SshAttr {
    #[strum(serialize = "Source IP")]
    SrcAddr,
    #[strum(serialize = "Source Port")]
    SrcPort,
    #[strum(serialize = "Destination IP")]
    DstAddr,
    #[strum(serialize = "Destination Port")]
    DstPort,
    #[strum(serialize = "Protocol Number")]
    Proto,
    #[strum(serialize = "Duration")]
    Duration,
    #[strum(serialize = "Packets Sent")]
    OrigPkts,
    #[strum(serialize = "Packets Received")]
    RespPkts,
    #[strum(serialize = "Layer 2 Bytes Sent")]
    OrigL2Bytes,
    #[strum(serialize = "Layer 2 Bytes Received")]
    RespL2Bytes,
    #[strum(serialize = "Client")]
    Client,
    #[strum(serialize = "Server")]
    Server,
    #[strum(serialize = "Cipher Algorithm")]
    CipherAlg,
    #[strum(serialize = "MAC Algorithms")]
    MacAlg,
    #[strum(serialize = "Compression Algorithm")]
    CompressionAlg,
    #[strum(serialize = "Kex Exchange Algorithm")]
    KexAlg,
    #[strum(serialize = "Host Key Algorithm")]
    HostKeyAlg,
    #[strum(serialize = "HASSH Algorithms")]
    HasshAlgorithms,
    #[strum(serialize = "HASSH")]
    Hassh,
    #[strum(serialize = "HASSH Server Algorithm")]
    HasshServerAlgorithms,
    #[strum(serialize = "HASSH Server")]
    HasshServer,
    #[strum(serialize = "Client Signed Host Key Algorithm")]
    ClientShka,
    #[strum(serialize = "Server Signed Host Key Algorithm")]
    ServerShka,
}

#[derive(Debug, EnumString, PartialEq, EnumIter, Display)]
pub enum TlsAttr {
    #[strum(serialize = "Source IP")]
    SrcAddr,
    #[strum(serialize = "Source Port")]
    SrcPort,
    #[strum(serialize = "Destination IP")]
    DstAddr,
    #[strum(serialize = "Destination Port")]
    DstPort,
    #[strum(serialize = "Protocol Number")]
    Proto,
    #[strum(serialize = "Duration")]
    Duration,
    #[strum(serialize = "Packets Sent")]
    OrigPkts,
    #[strum(serialize = "Packets Received")]
    RespPkts,
    #[strum(serialize = "Layer 2 Bytes Sent")]
    OrigL2Bytes,
    #[strum(serialize = "Layer 2 Bytes Received")]
    RespL2Bytes,
    #[strum(serialize = "Server Name")]
    ServerName,
    #[strum(serialize = "ALPN Protocol")]
    AlpnProtocol,
    #[strum(serialize = "JA3 Fingerprint")]
    Ja3,
    #[strum(serialize = "TLS Version")]
    Version,
    #[strum(serialize = "Client Cipher Suites")]
    ClientCipherSuites,
    #[strum(serialize = "Client Extensions")]
    ClientExtensions,
    #[strum(serialize = "Cipher")]
    Cipher,
    #[strum(serialize = "Extensions")]
    Extensions,
    #[strum(serialize = "JA3S Fingerprint")]
    Ja3s,
    #[strum(serialize = "Certificate Serial Number")]
    Serial,
    #[strum(serialize = "Subject Country")]
    SubjectCountry,
    #[strum(serialize = "Subject Organization Name")]
    SubjectOrgName,
    #[strum(serialize = "Common Name")]
    SubjectCommonName,
    #[strum(serialize = "Validity Start")]
    ValidityNotBefore,
    #[strum(serialize = "Validity End")]
    ValidityNotAfter,
    #[strum(serialize = "Subject Alternative Name")]
    SubjectAltName,
    #[strum(serialize = "Issuer Country")]
    IssuerCountry,
    #[strum(serialize = "Issuer Organization Name")]
    IssuerOrgName,
    #[strum(serialize = "Issuer Organization Unit Name")]
    IssuerOrgUnitName,
    #[strum(serialize = "Issuer Common Name")]
    IssuerCommonName,
    #[strum(serialize = "Last Alert Message")]
    LastAlert,
}

/// The attributes of a `MalformedDns` raw event, one per field of
/// [`review_protocol::types::raw_event::MalformedDns`].
#[derive(Debug, EnumString, PartialEq, EnumIter, Display)]
pub enum MalformedDnsAttr {
    #[strum(serialize = "Source IP")]
    SrcAddr,
    #[strum(serialize = "Source Port")]
    SrcPort,
    #[strum(serialize = "Destination IP")]
    DstAddr,
    #[strum(serialize = "Destination Port")]
    DstPort,
    #[strum(serialize = "Protocol Number")]
    Proto,
    #[strum(serialize = "Start Time")]
    StartTime,
    #[strum(serialize = "Duration")]
    Duration,
    #[strum(serialize = "Packets Sent")]
    OrigPkts,
    #[strum(serialize = "Packets Received")]
    RespPkts,
    #[strum(serialize = "Layer 2 Bytes Sent")]
    OrigL2Bytes,
    #[strum(serialize = "Layer 2 Bytes Received")]
    RespL2Bytes,
    #[strum(serialize = "Transaction ID")]
    TransId,
    #[strum(serialize = "Flags")]
    Flags,
    #[strum(serialize = "Question Count")]
    QuestionCount,
    #[strum(serialize = "Answer Count")]
    AnswerCount,
    #[strum(serialize = "Authority Count")]
    AuthorityCount,
    #[strum(serialize = "Additional Count")]
    AdditionalCount,
    #[strum(serialize = "Query Count")]
    QueryCount,
    #[strum(serialize = "Response Count")]
    RespCount,
    #[strum(serialize = "Query Bytes")]
    QueryBytes,
    #[strum(serialize = "Response Bytes")]
    RespBytes,
    #[strum(serialize = "Query Body")]
    QueryBody,
    #[strum(serialize = "Response Body")]
    RespBody,
}

/// The attributes of an `Icmp` raw event, one per field of
/// [`review_protocol::types::raw_event::Icmp`].
#[derive(Debug, EnumString, PartialEq, EnumIter, Display)]
pub enum IcmpAttr {
    #[strum(serialize = "Source IP")]
    SrcAddr,
    #[strum(serialize = "Destination IP")]
    DstAddr,
    #[strum(serialize = "Protocol Number")]
    Proto,
    #[strum(serialize = "Start Time")]
    StartTime,
    #[strum(serialize = "Duration")]
    Duration,
    #[strum(serialize = "Packets Sent")]
    OrigPkts,
    #[strum(serialize = "Packets Received")]
    RespPkts,
    #[strum(serialize = "Layer 2 Bytes Sent")]
    OrigL2Bytes,
    #[strum(serialize = "Layer 2 Bytes Received")]
    RespL2Bytes,
    #[strum(serialize = "ICMP Type")]
    IcmpType,
    #[strum(serialize = "ICMP Code")]
    IcmpCode,
    #[strum(serialize = "Identifier")]
    Id,
    #[strum(serialize = "Sequence Number")]
    SeqNum,
    #[strum(serialize = "Data Length")]
    DataLen,
    #[strum(serialize = "Payload")]
    Payload,
}

/// The attributes of a `ProcessCreate` raw event, one per field of
/// [`review_protocol::types::raw_event::ProcessCreate`] except the host header
/// `endpoint`, which has no attribute.
#[derive(Debug, EnumString, PartialEq, EnumIter, Display)]
pub enum ProcessCreateAttr {
    #[strum(serialize = "Agent Name")]
    AgentName,
    #[strum(serialize = "Agent ID")]
    AgentId,
    #[strum(serialize = "Process GUID")]
    ProcessGuid,
    #[strum(serialize = "Process ID")]
    ProcessId,
    #[strum(serialize = "Image")]
    Image,
    #[strum(serialize = "File Version")]
    FileVersion,
    #[strum(serialize = "Description")]
    Description,
    #[strum(serialize = "Product")]
    Product,
    #[strum(serialize = "Company")]
    Company,
    #[strum(serialize = "Original Filename")]
    OriginalFileName,
    #[strum(serialize = "Command Line")]
    CommandLine,
    #[strum(serialize = "Current Directory")]
    CurrentDirectory,
    #[strum(serialize = "User")]
    User,
    #[strum(serialize = "Logon GUID")]
    LogonGuid,
    #[strum(serialize = "Logon ID")]
    LogonId,
    #[strum(serialize = "Terminal Session ID")]
    TerminalSessionId,
    #[strum(serialize = "Integrity Level")]
    IntegrityLevel,
    #[strum(serialize = "Hashes")]
    Hashes,
    #[strum(serialize = "Parent Process GUID")]
    ParentProcessGuid,
    #[strum(serialize = "Parent Process ID")]
    ParentProcessId,
    #[strum(serialize = "Parent Image")]
    ParentImage,
    #[strum(serialize = "Parent Command Line")]
    ParentCommandLine,
    #[strum(serialize = "Parent User")]
    ParentUser,
    #[strum(serialize = "Logon ID Full")]
    LogonIdFull,
}

/// The attributes of a `FileCreateTime` raw event, one per field of
/// [`review_protocol::types::raw_event::FileCreateTime`] except the host header
/// `endpoint`, which has no attribute.
#[derive(Debug, EnumString, PartialEq, EnumIter, Display)]
pub enum FileCreateTimeAttr {
    #[strum(serialize = "Agent Name")]
    AgentName,
    #[strum(serialize = "Agent ID")]
    AgentId,
    #[strum(serialize = "Process GUID")]
    ProcessGuid,
    #[strum(serialize = "Process ID")]
    ProcessId,
    #[strum(serialize = "Image")]
    Image,
    #[strum(serialize = "Target Filename")]
    TargetFilename,
    #[strum(serialize = "Creation Time")]
    CreationUtcTime,
    #[strum(serialize = "Previous Creation Time")]
    PreviousCreationUtcTime,
    #[strum(serialize = "User")]
    User,
}

/// The attributes of a `NetworkConnect` raw event, one per field of
/// [`review_protocol::types::raw_event::NetworkConnect`] except the host header
/// `endpoint`, which has no attribute.
#[derive(Debug, EnumString, PartialEq, EnumIter, Display)]
pub enum NetworkConnectAttr {
    #[strum(serialize = "Agent Name")]
    AgentName,
    #[strum(serialize = "Agent ID")]
    AgentId,
    #[strum(serialize = "Process GUID")]
    ProcessGuid,
    #[strum(serialize = "Process ID")]
    ProcessId,
    #[strum(serialize = "Image")]
    Image,
    #[strum(serialize = "User")]
    User,
    #[strum(serialize = "Protocol")]
    Protocol,
    #[strum(serialize = "Initiated")]
    Initiated,
    #[strum(serialize = "Source Is IPv6")]
    SourceIsIpv6,
    #[strum(serialize = "Source IP")]
    SourceIp,
    #[strum(serialize = "Source Hostname")]
    SourceHostname,
    #[strum(serialize = "Source Port")]
    SourcePort,
    #[strum(serialize = "Source Port Name")]
    SourcePortName,
    #[strum(serialize = "Destination Is IPv6")]
    DestinationIsIpv6,
    #[strum(serialize = "Destination IP")]
    DestinationIp,
    #[strum(serialize = "Destination Hostname")]
    DestinationHostname,
    #[strum(serialize = "Destination Port")]
    DestinationPort,
    #[strum(serialize = "Destination Port Name")]
    DestinationPortName,
}

/// The attributes of a `ProcessTerminate` raw event, one per field of
/// [`review_protocol::types::raw_event::ProcessTerminate`] except the host
/// header `endpoint`, which has no attribute.
#[derive(Debug, EnumString, PartialEq, EnumIter, Display)]
pub enum ProcessTerminateAttr {
    #[strum(serialize = "Agent Name")]
    AgentName,
    #[strum(serialize = "Agent ID")]
    AgentId,
    #[strum(serialize = "Process GUID")]
    ProcessGuid,
    #[strum(serialize = "Process ID")]
    ProcessId,
    #[strum(serialize = "Image")]
    Image,
    #[strum(serialize = "User")]
    User,
}

/// The attributes of a `DriverLoad` raw event, one per field of
/// [`review_protocol::types::raw_event::DriverLoad`] except the host header
/// `endpoint`, which has no attribute.
#[derive(Debug, EnumString, PartialEq, EnumIter, Display)]
pub enum DriverLoadAttr {
    #[strum(serialize = "Agent Name")]
    AgentName,
    #[strum(serialize = "Agent ID")]
    AgentId,
    #[strum(serialize = "Image Loaded")]
    ImageLoaded,
    #[strum(serialize = "Hashes")]
    Hashes,
    #[strum(serialize = "Signed")]
    Signed,
    #[strum(serialize = "Signature")]
    Signature,
    #[strum(serialize = "Signature Status")]
    SignatureStatus,
}

/// The attributes of an `ImageLoad` raw event, one per field of
/// [`review_protocol::types::raw_event::ImageLoad`] except the host header
/// `endpoint`, which has no attribute.
#[derive(Debug, EnumString, PartialEq, EnumIter, Display)]
pub enum ImageLoadAttr {
    #[strum(serialize = "Agent Name")]
    AgentName,
    #[strum(serialize = "Agent ID")]
    AgentId,
    #[strum(serialize = "Process GUID")]
    ProcessGuid,
    #[strum(serialize = "Process ID")]
    ProcessId,
    #[strum(serialize = "Image")]
    Image,
    #[strum(serialize = "Image Loaded")]
    ImageLoaded,
    #[strum(serialize = "File Version")]
    FileVersion,
    #[strum(serialize = "Description")]
    Description,
    #[strum(serialize = "Product")]
    Product,
    #[strum(serialize = "Company")]
    Company,
    #[strum(serialize = "Original Filename")]
    OriginalFileName,
    #[strum(serialize = "Hashes")]
    Hashes,
    #[strum(serialize = "Signed")]
    Signed,
    #[strum(serialize = "Signature")]
    Signature,
    #[strum(serialize = "Signature Status")]
    SignatureStatus,
    #[strum(serialize = "User")]
    User,
}

/// The attributes of a `CreateRemoteThread` raw event, one per field of
/// [`review_protocol::types::raw_event::CreateRemoteThread`] except the host
/// header `endpoint`, which has no attribute.
#[derive(Debug, EnumString, PartialEq, EnumIter, Display)]
pub enum CreateRemoteThreadAttr {
    #[strum(serialize = "Agent Name")]
    AgentName,
    #[strum(serialize = "Agent ID")]
    AgentId,
    #[strum(serialize = "Source Process GUID")]
    SourceProcessGuid,
    #[strum(serialize = "Source Process ID")]
    SourceProcessId,
    #[strum(serialize = "Source Image")]
    SourceImage,
    #[strum(serialize = "Target Process GUID")]
    TargetProcessGuid,
    #[strum(serialize = "Target Process ID")]
    TargetProcessId,
    #[strum(serialize = "Target Image")]
    TargetImage,
    #[strum(serialize = "New Thread ID")]
    NewThreadId,
    #[strum(serialize = "Start Address")]
    StartAddress,
    #[strum(serialize = "Start Module")]
    StartModule,
    #[strum(serialize = "Start Function")]
    StartFunction,
    #[strum(serialize = "Source User")]
    SourceUser,
    #[strum(serialize = "Target User")]
    TargetUser,
}

/// The attributes of a `RawAccessRead` raw event, one per field of
/// [`review_protocol::types::raw_event::RawAccessRead`] except the host header
/// `endpoint`, which has no attribute.
#[derive(Debug, EnumString, PartialEq, EnumIter, Display)]
pub enum RawAccessReadAttr {
    #[strum(serialize = "Agent Name")]
    AgentName,
    #[strum(serialize = "Agent ID")]
    AgentId,
    #[strum(serialize = "Process GUID")]
    ProcessGuid,
    #[strum(serialize = "Process ID")]
    ProcessId,
    #[strum(serialize = "Image")]
    Image,
    #[strum(serialize = "Device")]
    Device,
    #[strum(serialize = "User")]
    User,
}

/// The attributes of a `ProcessAccess` raw event, one per field of
/// [`review_protocol::types::raw_event::ProcessAccess`] except the host header
/// `endpoint`, which has no attribute.
#[derive(Debug, EnumString, PartialEq, EnumIter, Display)]
pub enum ProcessAccessAttr {
    #[strum(serialize = "Agent Name")]
    AgentName,
    #[strum(serialize = "Agent ID")]
    AgentId,
    #[strum(serialize = "Source Process GUID")]
    SourceProcessGuid,
    #[strum(serialize = "Source Process ID")]
    SourceProcessId,
    #[strum(serialize = "Source Thread ID")]
    SourceThreadId,
    #[strum(serialize = "Source Image")]
    SourceImage,
    #[strum(serialize = "Target Process GUID")]
    TargetProcessGuid,
    #[strum(serialize = "Target Process ID")]
    TargetProcessId,
    #[strum(serialize = "Target Image")]
    TargetImage,
    #[strum(serialize = "Granted Access")]
    GrantedAccess,
    #[strum(serialize = "Call Trace")]
    CallTrace,
    #[strum(serialize = "Source User")]
    SourceUser,
    #[strum(serialize = "Target User")]
    TargetUser,
}

/// The attributes of a `FileCreate` raw event, one per field of
/// [`review_protocol::types::raw_event::FileCreate`] except the host header
/// `endpoint`, which has no attribute.
#[derive(Debug, EnumString, PartialEq, EnumIter, Display)]
pub enum FileCreateAttr {
    #[strum(serialize = "Agent Name")]
    AgentName,
    #[strum(serialize = "Agent ID")]
    AgentId,
    #[strum(serialize = "Process GUID")]
    ProcessGuid,
    #[strum(serialize = "Process ID")]
    ProcessId,
    #[strum(serialize = "Image")]
    Image,
    #[strum(serialize = "Target Filename")]
    TargetFilename,
    #[strum(serialize = "Creation Time")]
    CreationUtcTime,
    #[strum(serialize = "User")]
    User,
}

/// The attributes of a `RegistryObjectAddDel` raw event, one per field of
/// [`review_protocol::types::raw_event::RegistryObjectAddDel`] except the host
/// header `endpoint`, which has no attribute.
#[derive(Debug, EnumString, PartialEq, EnumIter, Display)]
pub enum RegistryObjectAddDelAttr {
    #[strum(serialize = "Agent Name")]
    AgentName,
    #[strum(serialize = "Agent ID")]
    AgentId,
    #[strum(serialize = "Event Type")]
    EventType,
    #[strum(serialize = "Process GUID")]
    ProcessGuid,
    #[strum(serialize = "Process ID")]
    ProcessId,
    #[strum(serialize = "Image")]
    Image,
    #[strum(serialize = "Target Object")]
    TargetObject,
    #[strum(serialize = "User")]
    User,
}

/// The attributes of a `RegistryValueSet` raw event, one per field of
/// [`review_protocol::types::raw_event::RegistryValueSet`] except the host
/// header `endpoint`, which has no attribute.
#[derive(Debug, EnumString, PartialEq, EnumIter, Display)]
pub enum RegistryValueSetAttr {
    #[strum(serialize = "Agent Name")]
    AgentName,
    #[strum(serialize = "Agent ID")]
    AgentId,
    #[strum(serialize = "Event Type")]
    EventType,
    #[strum(serialize = "Process GUID")]
    ProcessGuid,
    #[strum(serialize = "Process ID")]
    ProcessId,
    #[strum(serialize = "Image")]
    Image,
    #[strum(serialize = "Target Object")]
    TargetObject,
    #[strum(serialize = "Details")]
    Details,
    #[strum(serialize = "User")]
    User,
}

/// The attributes of a `RegistryKeyRename` raw event, one per field of
/// [`review_protocol::types::raw_event::RegistryKeyRename`] except the host
/// header `endpoint`, which has no attribute.
#[derive(Debug, EnumString, PartialEq, EnumIter, Display)]
pub enum RegistryKeyRenameAttr {
    #[strum(serialize = "Agent Name")]
    AgentName,
    #[strum(serialize = "Agent ID")]
    AgentId,
    #[strum(serialize = "Event Type")]
    EventType,
    #[strum(serialize = "Process GUID")]
    ProcessGuid,
    #[strum(serialize = "Process ID")]
    ProcessId,
    #[strum(serialize = "Image")]
    Image,
    #[strum(serialize = "Target Object")]
    TargetObject,
    #[strum(serialize = "New Name")]
    NewName,
    #[strum(serialize = "User")]
    User,
}

/// The attributes of a `FileCreateStreamHash` raw event, one per field of
/// [`review_protocol::types::raw_event::FileCreateStreamHash`] except the host
/// header `endpoint`, which has no attribute.
#[derive(Debug, EnumString, PartialEq, EnumIter, Display)]
pub enum FileCreateStreamHashAttr {
    #[strum(serialize = "Agent Name")]
    AgentName,
    #[strum(serialize = "Agent ID")]
    AgentId,
    #[strum(serialize = "Process GUID")]
    ProcessGuid,
    #[strum(serialize = "Process ID")]
    ProcessId,
    #[strum(serialize = "Image")]
    Image,
    #[strum(serialize = "Target Filename")]
    TargetFilename,
    #[strum(serialize = "Creation Time")]
    CreationUtcTime,
    #[strum(serialize = "Hashes")]
    Hash,
    #[strum(serialize = "Contents")]
    Contents,
    #[strum(serialize = "User")]
    User,
}

/// The attributes of a `PipeEvent` raw event, one per field of
/// [`review_protocol::types::raw_event::PipeEvent`] except the host header
/// `endpoint`, which has no attribute.
#[derive(Debug, EnumString, PartialEq, EnumIter, Display)]
pub enum PipeEventAttr {
    #[strum(serialize = "Agent Name")]
    AgentName,
    #[strum(serialize = "Agent ID")]
    AgentId,
    #[strum(serialize = "Event Type")]
    EventType,
    #[strum(serialize = "Process GUID")]
    ProcessGuid,
    #[strum(serialize = "Process ID")]
    ProcessId,
    #[strum(serialize = "Pipe Name")]
    PipeName,
    #[strum(serialize = "Image")]
    Image,
    #[strum(serialize = "User")]
    User,
}

/// The attributes of a `DnsQuery` raw event, one per field of
/// [`review_protocol::types::raw_event::DnsQuery`] except the host header
/// `endpoint`, which has no attribute.
#[derive(Debug, EnumString, PartialEq, EnumIter, Display)]
pub enum DnsQueryAttr {
    #[strum(serialize = "Agent Name")]
    AgentName,
    #[strum(serialize = "Agent ID")]
    AgentId,
    #[strum(serialize = "Process GUID")]
    ProcessGuid,
    #[strum(serialize = "Process ID")]
    ProcessId,
    #[strum(serialize = "Query Name")]
    QueryName,
    #[strum(serialize = "Query Status")]
    QueryStatus,
    #[strum(serialize = "Query Results")]
    QueryResults,
    #[strum(serialize = "Image")]
    Image,
    #[strum(serialize = "User")]
    User,
}

/// The attributes of a `FileDelete` raw event, one per field of
/// [`review_protocol::types::raw_event::FileDelete`] except the host header
/// `endpoint`, which has no attribute.
#[derive(Debug, EnumString, PartialEq, EnumIter, Display)]
pub enum FileDeleteAttr {
    #[strum(serialize = "Agent Name")]
    AgentName,
    #[strum(serialize = "Agent ID")]
    AgentId,
    #[strum(serialize = "Process GUID")]
    ProcessGuid,
    #[strum(serialize = "Process ID")]
    ProcessId,
    #[strum(serialize = "User")]
    User,
    #[strum(serialize = "Image")]
    Image,
    #[strum(serialize = "Target Filename")]
    TargetFilename,
    #[strum(serialize = "Hashes")]
    Hashes,
    #[strum(serialize = "Executable Flag")]
    IsExecutable,
    #[strum(serialize = "Archived Flag")]
    Archived,
}

/// The attributes of a `ProcessTamper` raw event, one per field of
/// [`review_protocol::types::raw_event::ProcessTamper`] except the host header
/// `endpoint`, which has no attribute.
#[derive(Debug, EnumString, PartialEq, EnumIter, Display)]
pub enum ProcessTamperAttr {
    #[strum(serialize = "Agent Name")]
    AgentName,
    #[strum(serialize = "Agent ID")]
    AgentId,
    #[strum(serialize = "Process GUID")]
    ProcessGuid,
    #[strum(serialize = "Process ID")]
    ProcessId,
    #[strum(serialize = "Image")]
    Image,
    #[strum(serialize = "Tamper Type")]
    TamperType,
    #[strum(serialize = "User")]
    User,
}

/// The attributes of a `FileDeleteDetected` raw event, one per field of
/// [`review_protocol::types::raw_event::FileDeleteDetected`] except the host
/// header `endpoint`, which has no attribute.
#[derive(Debug, EnumString, PartialEq, EnumIter, Display)]
pub enum FileDeleteDetectedAttr {
    #[strum(serialize = "Agent Name")]
    AgentName,
    #[strum(serialize = "Agent ID")]
    AgentId,
    #[strum(serialize = "Process GUID")]
    ProcessGuid,
    #[strum(serialize = "Process ID")]
    ProcessId,
    #[strum(serialize = "User")]
    User,
    #[strum(serialize = "Image")]
    Image,
    #[strum(serialize = "Target Filename")]
    TargetFilename,
    #[strum(serialize = "Hashes")]
    Hashes,
    #[strum(serialize = "Executable Flag")]
    IsExecutable,
}

/// The attributes of a `Netflow5` raw event, one per field of
/// [`review_protocol::types::raw_event::Netflow5`].
#[derive(Debug, EnumString, PartialEq, EnumIter, Display)]
pub enum Netflow5Attr {
    #[strum(serialize = "Source IP")]
    SrcAddr,
    #[strum(serialize = "Destination IP")]
    DstAddr,
    #[strum(serialize = "Next Hop IP")]
    NextHop,
    #[strum(serialize = "Input Interface")]
    Input,
    #[strum(serialize = "Output Interface")]
    Output,
    #[strum(serialize = "Packets")]
    DPkts,
    #[strum(serialize = "Bytes")]
    DOctets,
    #[strum(serialize = "First Packet Time")]
    First,
    #[strum(serialize = "Last Packet Time")]
    Last,
    #[strum(serialize = "Source Port")]
    SrcPort,
    #[strum(serialize = "Destination Port")]
    DstPort,
    #[strum(serialize = "TCP Flags")]
    TcpFlags,
    #[strum(serialize = "Protocol Number")]
    Prot,
    #[strum(serialize = "Type Of Service")]
    Tos,
    #[strum(serialize = "Source AS Number")]
    SrcAs,
    #[strum(serialize = "Destination AS Number")]
    DstAs,
    #[strum(serialize = "Source Prefix Mask")]
    SrcMask,
    #[strum(serialize = "Destination Prefix Mask")]
    DstMask,
    #[strum(serialize = "Sequence Number")]
    Sequence,
    #[strum(serialize = "Engine Type")]
    EngineType,
    #[strum(serialize = "Engine ID")]
    EngineId,
    #[strum(serialize = "Sampling Mode")]
    SamplingMode,
    #[strum(serialize = "Sampling Rate")]
    SamplingRate,
}

/// The attributes of a `Netflow9` raw event, one per field of
/// [`review_protocol::types::raw_event::Netflow9`].
#[derive(Debug, EnumString, PartialEq, EnumIter, Display)]
pub enum Netflow9Attr {
    #[strum(serialize = "Sequence Number")]
    Sequence,
    #[strum(serialize = "Source ID")]
    SourceId,
    #[strum(serialize = "Template ID")]
    TemplateId,
    #[strum(serialize = "Source IP")]
    SrcAddr,
    #[strum(serialize = "Source Port")]
    SrcPort,
    #[strum(serialize = "Destination IP")]
    DstAddr,
    #[strum(serialize = "Destination Port")]
    DstPort,
    #[strum(serialize = "Protocol Number")]
    Proto,
    #[strum(serialize = "Contents")]
    Contents,
}

/// The attributes of a `WindowsEventLog` raw event, one per field of
/// [`review_protocol::types::raw_event::WindowsEventLog`] except the host
/// header `endpoint`, which has no attribute.
///
/// The list field `event_data` is a single attribute, not one per element.
#[derive(Debug, EnumString, PartialEq, EnumIter, Display)]
pub enum WindowsEventLogAttr {
    #[strum(serialize = "Channel")]
    Channel,
    #[strum(serialize = "Provider")]
    Provider,
    #[strum(serialize = "Event ID")]
    EventId,
    #[strum(serialize = "Version")]
    Version,
    #[strum(serialize = "Level")]
    Level,
    #[strum(serialize = "Task")]
    Task,
    #[strum(serialize = "Opcode")]
    Opcode,
    #[strum(serialize = "Keywords")]
    Keywords,
    #[strum(serialize = "Record ID")]
    RecordId,
    #[strum(serialize = "Computer")]
    Computer,
    #[strum(serialize = "User SID")]
    UserSid,
    #[strum(serialize = "Event Data")]
    EventData,
    #[strum(serialize = "User Data XML")]
    UserDataXml,
}

/// The attributes of a `Journald` raw event, one per field of
/// [`review_protocol::types::raw_event::Journald`] except the host header
/// `endpoint`, which has no attribute.
///
/// The list field `fields` is a single attribute, not one per element.
#[derive(Debug, EnumString, PartialEq, EnumIter, Display)]
pub enum JournaldAttr {
    #[strum(serialize = "Fields")]
    Fields,
}

/// The attributes of an `Auditd` raw event, one per field of
/// [`review_protocol::types::raw_event::Auditd`] except the host header
/// `endpoint`, which has no attribute.
///
/// The list field `records` is a single attribute, not one per element.
#[derive(Debug, EnumString, PartialEq, EnumIter, Display)]
pub enum AuditdAttr {
    #[strum(serialize = "Serial")]
    Serial,
    #[strum(serialize = "Records")]
    Records,
}

#[cfg(test)]
mod tests {
    use std::fmt::{Debug, Display};

    use review_protocol::types::raw_event;
    use strum::IntoEnumIterator;

    use super::*;

    const INVALID_ATTR_FIELD_NAME: &str = "invalid-attr-field";
    const RAW_EVENT_KIND_COUNT: usize = 44;
    const HOST_HEADER_VARIANT: &str = "Endpoint";
    const HOST_HEADER_NAMES: [&str; 2] = ["Endpoint", "endpoint"];

    /// Asserts that every display name of `A` parses, for `kind`, to the
    /// matching variant wrapped by `wrap`, that the display names are
    /// unique, that an unknown name is rejected, and that no variant stands
    /// for the host header. Returns the display names.
    fn assert_attr_names_parse<A>(
        kind: RawEventKind,
        wrap: fn(A) -> RawEventAttrKind,
    ) -> Vec<String>
    where
        A: IntoEnumIterator + Display + Debug,
    {
        let mut names: Vec<String> = A::iter().map(|attr| attr.to_string()).collect();
        assert!(!names.is_empty(), "{kind:?} has no attributes");
        let count = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), count, "{kind:?} has a duplicate display name");

        for attr in A::iter() {
            assert_ne!(
                format!("{attr:?}"),
                HOST_HEADER_VARIANT,
                "{kind:?} has a host header variant"
            );
            let name = attr.to_string();
            let parsed = RawEventAttrKind::from_kind_and_attr_name(&kind, &name)
                .unwrap_or_else(|e| panic!("{kind:?} rejected {name:?}: {e}"));
            assert_eq!(parsed, wrap(attr), "{kind:?} parsed {name:?} wrongly");
        }

        assert!(
            RawEventAttrKind::from_kind_and_attr_name(&kind, INVALID_ATTR_FIELD_NAME).is_err(),
            "{kind:?} accepted an unknown attribute name"
        );
        for name in HOST_HEADER_NAMES {
            assert!(
                RawEventAttrKind::from_kind_and_attr_name(&kind, name).is_err(),
                "{kind:?} accepted the host header name {name:?}"
            );
        }
        names
    }

    /// Checks the attribute names of `kind` and returns them. The match has
    /// one arm per kind and no wildcard, so a kind without a check fails to
    /// compile.
    fn check_kind(kind: RawEventKind) -> Vec<String> {
        match kind {
            RawEventKind::Conn => assert_attr_names_parse(kind, RawEventAttrKind::Conn),
            RawEventKind::Dns => assert_attr_names_parse(kind, RawEventAttrKind::Dns),
            RawEventKind::Http => assert_attr_names_parse(kind, RawEventAttrKind::Http),
            RawEventKind::Rdp => assert_attr_names_parse(kind, RawEventAttrKind::Rdp),
            RawEventKind::Smtp => assert_attr_names_parse(kind, RawEventAttrKind::Smtp),
            RawEventKind::Ntlm => assert_attr_names_parse(kind, RawEventAttrKind::Ntlm),
            RawEventKind::Kerberos => assert_attr_names_parse(kind, RawEventAttrKind::Kerberos),
            RawEventKind::Ssh => assert_attr_names_parse(kind, RawEventAttrKind::Ssh),
            RawEventKind::DceRpc => assert_attr_names_parse(kind, RawEventAttrKind::DceRpc),
            RawEventKind::Ftp => assert_attr_names_parse(kind, RawEventAttrKind::Ftp),
            RawEventKind::Mqtt => assert_attr_names_parse(kind, RawEventAttrKind::Mqtt),
            RawEventKind::Ldap => assert_attr_names_parse(kind, RawEventAttrKind::Ldap),
            RawEventKind::Tls => assert_attr_names_parse(kind, RawEventAttrKind::Tls),
            RawEventKind::Smb => assert_attr_names_parse(kind, RawEventAttrKind::Smb),
            RawEventKind::Nfs => assert_attr_names_parse(kind, RawEventAttrKind::Nfs),
            RawEventKind::Bootp => assert_attr_names_parse(kind, RawEventAttrKind::Bootp),
            RawEventKind::Dhcp => assert_attr_names_parse(kind, RawEventAttrKind::Dhcp),
            RawEventKind::Radius => assert_attr_names_parse(kind, RawEventAttrKind::Radius),
            RawEventKind::MalformedDns => {
                assert_attr_names_parse(kind, RawEventAttrKind::MalformedDns)
            }
            RawEventKind::Icmp => assert_attr_names_parse(kind, RawEventAttrKind::Icmp),
            RawEventKind::ProcessCreate => {
                assert_attr_names_parse(kind, RawEventAttrKind::ProcessCreate)
            }
            RawEventKind::FileCreateTime => {
                assert_attr_names_parse(kind, RawEventAttrKind::FileCreateTime)
            }
            RawEventKind::NetworkConnect => {
                assert_attr_names_parse(kind, RawEventAttrKind::NetworkConnect)
            }
            RawEventKind::ProcessTerminate => {
                assert_attr_names_parse(kind, RawEventAttrKind::ProcessTerminate)
            }
            RawEventKind::DriverLoad => assert_attr_names_parse(kind, RawEventAttrKind::DriverLoad),
            RawEventKind::ImageLoad => assert_attr_names_parse(kind, RawEventAttrKind::ImageLoad),
            RawEventKind::CreateRemoteThread => {
                assert_attr_names_parse(kind, RawEventAttrKind::CreateRemoteThread)
            }
            RawEventKind::RawAccessRead => {
                assert_attr_names_parse(kind, RawEventAttrKind::RawAccessRead)
            }
            RawEventKind::ProcessAccess => {
                assert_attr_names_parse(kind, RawEventAttrKind::ProcessAccess)
            }
            RawEventKind::FileCreate => assert_attr_names_parse(kind, RawEventAttrKind::FileCreate),
            RawEventKind::RegistryObjectAddDel => {
                assert_attr_names_parse(kind, RawEventAttrKind::RegistryObjectAddDel)
            }
            RawEventKind::RegistryValueSet => {
                assert_attr_names_parse(kind, RawEventAttrKind::RegistryValueSet)
            }
            RawEventKind::RegistryKeyRename => {
                assert_attr_names_parse(kind, RawEventAttrKind::RegistryKeyRename)
            }
            RawEventKind::FileCreateStreamHash => {
                assert_attr_names_parse(kind, RawEventAttrKind::FileCreateStreamHash)
            }
            RawEventKind::PipeEvent => assert_attr_names_parse(kind, RawEventAttrKind::PipeEvent),
            RawEventKind::DnsQuery => assert_attr_names_parse(kind, RawEventAttrKind::DnsQuery),
            RawEventKind::FileDelete => assert_attr_names_parse(kind, RawEventAttrKind::FileDelete),
            RawEventKind::ProcessTamper => {
                assert_attr_names_parse(kind, RawEventAttrKind::ProcessTamper)
            }
            RawEventKind::FileDeleteDetected => {
                assert_attr_names_parse(kind, RawEventAttrKind::FileDeleteDetected)
            }
            RawEventKind::Netflow5 => assert_attr_names_parse(kind, RawEventAttrKind::Netflow5),
            RawEventKind::Netflow9 => assert_attr_names_parse(kind, RawEventAttrKind::Netflow9),
            RawEventKind::WindowsEventLog => {
                assert_attr_names_parse(kind, RawEventAttrKind::WindowsEventLog)
            }
            RawEventKind::Journald => assert_attr_names_parse(kind, RawEventAttrKind::Journald),
            RawEventKind::Auditd => assert_attr_names_parse(kind, RawEventAttrKind::Auditd),
        }
    }

    #[test]
    fn every_kind_parses_every_attr_name() {
        // `RawEventKind` is serialized as an explicit `u32`, and every number
        // review-protocol assigns lies far below `u16::MAX`, so this visits
        // every kind.
        let kinds: Vec<RawEventKind> = (0..=u32::from(u16::MAX))
            .filter_map(|number| RawEventKind::try_from(number).ok())
            .collect();
        assert_eq!(kinds.len(), RAW_EVENT_KIND_COUNT);
        let names_by_kind: Vec<(RawEventKind, Vec<String>)> = kinds
            .into_iter()
            .map(|kind| (kind, check_kind(kind)))
            .collect();

        // Every display name of any kind parses for exactly the kinds that
        // have it, so a name belonging only to another kind is rejected.
        let all_names: Vec<&String> = names_by_kind.iter().flat_map(|(_, names)| names).collect();
        for (kind, names) in &names_by_kind {
            for name in &all_names {
                assert_eq!(
                    RawEventAttrKind::from_kind_and_attr_name(kind, name).is_ok(),
                    names.contains(name),
                    "{kind:?} and {name:?}"
                );
            }
        }
    }

    /// Asserts that the display names of `A`, in declaration order, are
    /// exactly `expected`.
    fn assert_display_names<A>(expected: &[&str])
    where
        A: IntoEnumIterator + Display,
    {
        let names: Vec<String> = A::iter().map(|attr| attr.to_string()).collect();
        assert_eq!(names, expected);
    }

    #[test]
    fn new_attr_enums_have_exact_display_names() {
        assert_display_names::<DriverLoadAttr>(&[
            "Agent Name",
            "Agent ID",
            "Image Loaded",
            "Hashes",
            "Signed",
            "Signature",
            "Signature Status",
        ]);
        assert_display_names::<CreateRemoteThreadAttr>(&[
            "Agent Name",
            "Agent ID",
            "Source Process GUID",
            "Source Process ID",
            "Source Image",
            "Target Process GUID",
            "Target Process ID",
            "Target Image",
            "New Thread ID",
            "Start Address",
            "Start Module",
            "Start Function",
            "Source User",
            "Target User",
        ]);
        assert_display_names::<RawAccessReadAttr>(&[
            "Agent Name",
            "Agent ID",
            "Process GUID",
            "Process ID",
            "Image",
            "Device",
            "User",
        ]);
        assert_display_names::<ProcessAccessAttr>(&[
            "Agent Name",
            "Agent ID",
            "Source Process GUID",
            "Source Process ID",
            "Source Thread ID",
            "Source Image",
            "Target Process GUID",
            "Target Process ID",
            "Target Image",
            "Granted Access",
            "Call Trace",
            "Source User",
            "Target User",
        ]);
        assert_display_names::<RegistryObjectAddDelAttr>(&[
            "Agent Name",
            "Agent ID",
            "Event Type",
            "Process GUID",
            "Process ID",
            "Image",
            "Target Object",
            "User",
        ]);
        assert_display_names::<WindowsEventLogAttr>(&[
            "Channel",
            "Provider",
            "Event ID",
            "Version",
            "Level",
            "Task",
            "Opcode",
            "Keywords",
            "Record ID",
            "Computer",
            "User SID",
            "Event Data",
            "User Data XML",
        ]);
        assert_display_names::<JournaldAttr>(&["Fields"]);
        assert_display_names::<AuditdAttr>(&["Serial", "Records"]);
    }

    #[test]
    fn logon_id_full_belongs_to_process_create_only() {
        assert_eq!(
            ProcessCreateAttr::iter().next_back(),
            Some(ProcessCreateAttr::LogonIdFull)
        );
        assert_eq!(
            RawEventAttrKind::from_kind_and_attr_name(
                &RawEventKind::ProcessCreate,
                "Logon ID Full"
            )
            .ok(),
            Some(RawEventAttrKind::ProcessCreate(
                ProcessCreateAttr::LogonIdFull
            ))
        );
        assert!(
            RawEventAttrKind::from_kind_and_attr_name(
                &RawEventKind::ProcessTerminate,
                "Logon ID Full"
            )
            .is_err()
        );
    }

    #[test]
    fn new_kind_attr_names_stay_with_their_kinds() {
        // A name of a new kind is rejected for an existing kind, and a name
        // of an existing kind absent from a new kind is rejected for it.
        let rejected = [
            (RawEventKind::ProcessCreate, "Granted Access"),
            (RawEventKind::ImageLoad, "Device"),
            (RawEventKind::ProcessAccess, "Command Line"),
            (RawEventKind::DriverLoad, "Command Line"),
            (RawEventKind::CreateRemoteThread, "Granted Access"),
            (RawEventKind::RawAccessRead, "Image Loaded"),
            (RawEventKind::RegistryObjectAddDel, "Details"),
            (RawEventKind::WindowsEventLog, "Agent Name"),
            (RawEventKind::Journald, "Records"),
            (RawEventKind::Auditd, "Fields"),
            (RawEventKind::Conn, "Event Data"),
        ];
        for (kind, name) in rejected {
            assert!(
                RawEventAttrKind::from_kind_and_attr_name(&kind, name).is_err(),
                "{kind:?} accepted {name:?}"
            );
        }
        assert_eq!(
            RawEventAttrKind::from_kind_and_attr_name(
                &RawEventKind::ProcessAccess,
                "Granted Access"
            )
            .ok(),
            Some(RawEventAttrKind::ProcessAccess(
                ProcessAccessAttr::GrantedAccess
            ))
        );
    }

    #[test]
    fn attr_name_of_another_kind_is_rejected() {
        assert!(
            RawEventAttrKind::from_kind_and_attr_name(
                &RawEventKind::Icmp,
                &IcmpAttr::IcmpType.to_string()
            )
            .is_ok()
        );
        assert!(
            RawEventAttrKind::from_kind_and_attr_name(
                &RawEventKind::Conn,
                &IcmpAttr::IcmpType.to_string()
            )
            .is_err()
        );
        assert!(
            RawEventAttrKind::from_kind_and_attr_name(
                &RawEventKind::Netflow9,
                &ProcessCreateAttr::CommandLine.to_string()
            )
            .is_err()
        );
    }

    /// Asserts that `listed` has no duplicate and holds, as a set, exactly
    /// the variants of `A`.
    fn assert_same_variants<A>(listed: &[A])
    where
        A: IntoEnumIterator + PartialEq + Debug,
    {
        for (i, variant) in listed.iter().enumerate() {
            assert!(
                !listed.iter().skip(i + 1).any(|other| other == variant),
                "{variant:?} is listed for more than one field"
            );
        }
        let all: Vec<A> = A::iter().collect();
        for variant in &all {
            assert!(listed.contains(variant), "{variant:?} has no field");
        }
        assert_eq!(listed.len(), all.len());
    }

    /// Checks that `$attr` has exactly one variant per field of
    /// `raw_event::$kind`, except the fields listed after `no_attr:`, which
    /// have no attribute. All fields expand to a destructuring pattern
    /// without `..`, so a missing, extra or misspelled field fails to
    /// compile; only the mapped variants are checked against
    /// `$attr::iter()`.
    macro_rules! assert_fields {
        (
            $kind:ident => $attr:ident {
                $($field:ident => $variant:ident),+ $(,)?
                $(; no_attr: $($no_attr:ident),+ $(,)?)?
            }
        ) => {{
            let _ = |body: &raw_event::$kind| {
                let raw_event::$kind { $($field: _,)+ $($($no_attr: _,)+)? } = body;
            };
            assert_same_variants(&[$($attr::$variant),+]);
        }};
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn new_attr_enums_match_body_fields() {
        assert_fields!(MalformedDns => MalformedDnsAttr {
            orig_addr => SrcAddr,
            orig_port => SrcPort,
            resp_addr => DstAddr,
            resp_port => DstPort,
            proto => Proto,
            start_time => StartTime,
            duration => Duration,
            orig_pkts => OrigPkts,
            resp_pkts => RespPkts,
            orig_l2_bytes => OrigL2Bytes,
            resp_l2_bytes => RespL2Bytes,
            trans_id => TransId,
            flags => Flags,
            question_count => QuestionCount,
            answer_count => AnswerCount,
            authority_count => AuthorityCount,
            additional_count => AdditionalCount,
            query_count => QueryCount,
            resp_count => RespCount,
            query_bytes => QueryBytes,
            resp_bytes => RespBytes,
            query_body => QueryBody,
            resp_body => RespBody,
        });

        assert_fields!(Icmp => IcmpAttr {
            orig_addr => SrcAddr,
            resp_addr => DstAddr,
            proto => Proto,
            start_time => StartTime,
            duration => Duration,
            orig_pkts => OrigPkts,
            resp_pkts => RespPkts,
            orig_l2_bytes => OrigL2Bytes,
            resp_l2_bytes => RespL2Bytes,
            icmp_type => IcmpType,
            icmp_code => IcmpCode,
            id => Id,
            seq_num => SeqNum,
            data_len => DataLen,
            payload => Payload,
        });

        assert_fields!(ProcessCreate => ProcessCreateAttr {
            agent_name => AgentName,
            agent_id => AgentId,
            process_guid => ProcessGuid,
            process_id => ProcessId,
            image => Image,
            file_version => FileVersion,
            description => Description,
            product => Product,
            company => Company,
            original_file_name => OriginalFileName,
            command_line => CommandLine,
            current_directory => CurrentDirectory,
            user => User,
            logon_guid => LogonGuid,
            logon_id => LogonId,
            terminal_session_id => TerminalSessionId,
            integrity_level => IntegrityLevel,
            hashes => Hashes,
            parent_process_guid => ParentProcessGuid,
            parent_process_id => ParentProcessId,
            parent_image => ParentImage,
            parent_command_line => ParentCommandLine,
            parent_user => ParentUser,
            logon_id_full => LogonIdFull;
            no_attr: endpoint
        });

        assert_fields!(FileCreateTime => FileCreateTimeAttr {
            agent_name => AgentName,
            agent_id => AgentId,
            process_guid => ProcessGuid,
            process_id => ProcessId,
            image => Image,
            target_filename => TargetFilename,
            creation_utc_time => CreationUtcTime,
            previous_creation_utc_time => PreviousCreationUtcTime,
            user => User;
            no_attr: endpoint
        });

        assert_fields!(NetworkConnect => NetworkConnectAttr {
            agent_name => AgentName,
            agent_id => AgentId,
            process_guid => ProcessGuid,
            process_id => ProcessId,
            image => Image,
            user => User,
            protocol => Protocol,
            initiated => Initiated,
            source_is_ipv6 => SourceIsIpv6,
            source_ip => SourceIp,
            source_hostname => SourceHostname,
            source_port => SourcePort,
            source_port_name => SourcePortName,
            destination_is_ipv6 => DestinationIsIpv6,
            destination_ip => DestinationIp,
            destination_hostname => DestinationHostname,
            destination_port => DestinationPort,
            destination_port_name => DestinationPortName;
            no_attr: endpoint
        });

        assert_fields!(ProcessTerminate => ProcessTerminateAttr {
            agent_name => AgentName,
            agent_id => AgentId,
            process_guid => ProcessGuid,
            process_id => ProcessId,
            image => Image,
            user => User;
            no_attr: endpoint
        });

        assert_fields!(DriverLoad => DriverLoadAttr {
            agent_name => AgentName,
            agent_id => AgentId,
            image_loaded => ImageLoaded,
            hashes => Hashes,
            signed => Signed,
            signature => Signature,
            signature_status => SignatureStatus;
            no_attr: endpoint
        });

        assert_fields!(ImageLoad => ImageLoadAttr {
            agent_name => AgentName,
            agent_id => AgentId,
            process_guid => ProcessGuid,
            process_id => ProcessId,
            image => Image,
            image_loaded => ImageLoaded,
            file_version => FileVersion,
            description => Description,
            product => Product,
            company => Company,
            original_file_name => OriginalFileName,
            hashes => Hashes,
            signed => Signed,
            signature => Signature,
            signature_status => SignatureStatus,
            user => User;
            no_attr: endpoint
        });

        assert_fields!(CreateRemoteThread => CreateRemoteThreadAttr {
            agent_name => AgentName,
            agent_id => AgentId,
            source_process_guid => SourceProcessGuid,
            source_process_id => SourceProcessId,
            source_image => SourceImage,
            target_process_guid => TargetProcessGuid,
            target_process_id => TargetProcessId,
            target_image => TargetImage,
            new_thread_id => NewThreadId,
            start_address => StartAddress,
            start_module => StartModule,
            start_function => StartFunction,
            source_user => SourceUser,
            target_user => TargetUser;
            no_attr: endpoint
        });

        assert_fields!(RawAccessRead => RawAccessReadAttr {
            agent_name => AgentName,
            agent_id => AgentId,
            process_guid => ProcessGuid,
            process_id => ProcessId,
            image => Image,
            device => Device,
            user => User;
            no_attr: endpoint
        });

        assert_fields!(ProcessAccess => ProcessAccessAttr {
            agent_name => AgentName,
            agent_id => AgentId,
            source_process_guid => SourceProcessGuid,
            source_process_id => SourceProcessId,
            source_thread_id => SourceThreadId,
            source_image => SourceImage,
            target_process_guid => TargetProcessGuid,
            target_process_id => TargetProcessId,
            target_image => TargetImage,
            granted_access => GrantedAccess,
            call_trace => CallTrace,
            source_user => SourceUser,
            target_user => TargetUser;
            no_attr: endpoint
        });

        assert_fields!(FileCreate => FileCreateAttr {
            agent_name => AgentName,
            agent_id => AgentId,
            process_guid => ProcessGuid,
            process_id => ProcessId,
            image => Image,
            target_filename => TargetFilename,
            creation_utc_time => CreationUtcTime,
            user => User;
            no_attr: endpoint
        });

        assert_fields!(RegistryObjectAddDel => RegistryObjectAddDelAttr {
            agent_name => AgentName,
            agent_id => AgentId,
            event_type => EventType,
            process_guid => ProcessGuid,
            process_id => ProcessId,
            image => Image,
            target_object => TargetObject,
            user => User;
            no_attr: endpoint
        });

        assert_fields!(RegistryValueSet => RegistryValueSetAttr {
            agent_name => AgentName,
            agent_id => AgentId,
            event_type => EventType,
            process_guid => ProcessGuid,
            process_id => ProcessId,
            image => Image,
            target_object => TargetObject,
            details => Details,
            user => User;
            no_attr: endpoint
        });

        assert_fields!(RegistryKeyRename => RegistryKeyRenameAttr {
            agent_name => AgentName,
            agent_id => AgentId,
            event_type => EventType,
            process_guid => ProcessGuid,
            process_id => ProcessId,
            image => Image,
            target_object => TargetObject,
            new_name => NewName,
            user => User;
            no_attr: endpoint
        });

        assert_fields!(FileCreateStreamHash => FileCreateStreamHashAttr {
            agent_name => AgentName,
            agent_id => AgentId,
            process_guid => ProcessGuid,
            process_id => ProcessId,
            image => Image,
            target_filename => TargetFilename,
            creation_utc_time => CreationUtcTime,
            hash => Hash,
            contents => Contents,
            user => User;
            no_attr: endpoint
        });

        assert_fields!(PipeEvent => PipeEventAttr {
            agent_name => AgentName,
            agent_id => AgentId,
            event_type => EventType,
            process_guid => ProcessGuid,
            process_id => ProcessId,
            pipe_name => PipeName,
            image => Image,
            user => User;
            no_attr: endpoint
        });

        assert_fields!(DnsQuery => DnsQueryAttr {
            agent_name => AgentName,
            agent_id => AgentId,
            process_guid => ProcessGuid,
            process_id => ProcessId,
            query_name => QueryName,
            query_status => QueryStatus,
            query_results => QueryResults,
            image => Image,
            user => User;
            no_attr: endpoint
        });

        assert_fields!(FileDelete => FileDeleteAttr {
            agent_name => AgentName,
            agent_id => AgentId,
            process_guid => ProcessGuid,
            process_id => ProcessId,
            user => User,
            image => Image,
            target_filename => TargetFilename,
            hashes => Hashes,
            is_executable => IsExecutable,
            archived => Archived;
            no_attr: endpoint
        });

        assert_fields!(ProcessTamper => ProcessTamperAttr {
            agent_name => AgentName,
            agent_id => AgentId,
            process_guid => ProcessGuid,
            process_id => ProcessId,
            image => Image,
            tamper_type => TamperType,
            user => User;
            no_attr: endpoint
        });

        assert_fields!(FileDeleteDetected => FileDeleteDetectedAttr {
            agent_name => AgentName,
            agent_id => AgentId,
            process_guid => ProcessGuid,
            process_id => ProcessId,
            user => User,
            image => Image,
            target_filename => TargetFilename,
            hashes => Hashes,
            is_executable => IsExecutable;
            no_attr: endpoint
        });

        assert_fields!(Netflow5 => Netflow5Attr {
            src_addr => SrcAddr,
            dst_addr => DstAddr,
            next_hop => NextHop,
            input => Input,
            output => Output,
            d_pkts => DPkts,
            d_octets => DOctets,
            first => First,
            last => Last,
            src_port => SrcPort,
            dst_port => DstPort,
            tcp_flags => TcpFlags,
            prot => Prot,
            tos => Tos,
            src_as => SrcAs,
            dst_as => DstAs,
            src_mask => SrcMask,
            dst_mask => DstMask,
            sequence => Sequence,
            engine_type => EngineType,
            engine_id => EngineId,
            sampling_mode => SamplingMode,
            sampling_rate => SamplingRate,
        });

        assert_fields!(Netflow9 => Netflow9Attr {
            sequence => Sequence,
            source_id => SourceId,
            template_id => TemplateId,
            orig_addr => SrcAddr,
            orig_port => SrcPort,
            resp_addr => DstAddr,
            resp_port => DstPort,
            proto => Proto,
            contents => Contents,
        });

        assert_fields!(WindowsEventLog => WindowsEventLogAttr {
            channel => Channel,
            provider => Provider,
            event_id => EventId,
            version => Version,
            level => Level,
            task => Task,
            opcode => Opcode,
            keywords => Keywords,
            record_id => RecordId,
            computer => Computer,
            user_sid => UserSid,
            event_data => EventData,
            user_data_xml => UserDataXml;
            no_attr: endpoint
        });

        assert_fields!(Journald => JournaldAttr {
            fields => Fields;
            no_attr: endpoint
        });

        assert_fields!(Auditd => AuditdAttr {
            serial => Serial,
            records => Records;
            no_attr: endpoint
        });
    }
}
