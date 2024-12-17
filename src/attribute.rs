use std::str::FromStr;

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use strum_macros::{Display, EnumIter, EnumString};

#[derive(Debug, Deserialize, Serialize, EnumString, PartialEq, EnumIter, Display)]
#[serde(rename_all = "snake_case")]
pub enum RawEventType {
    Bootp,
    Conn,
    Dhcp,
    Dns,
    Ftp,
    Http,
    Kerberos,
    Ldap,
    Log,
    Mqtt,
    Network,
    Nfs,
    Ntlm,
    Rdp,
    Smb,
    Smtp,
    Ssh,
    Tls,
    Window,
}

#[derive(Debug, PartialEq)]
pub enum RawEventKind {
    Bootp(BootpAttr),
    Conn(ConnAttr),
    Dhcp(DhcpAttr),
    Dns(DnsAttr),
    Ftp(FtpAttr),
    Http(HttpAttr),
    Kerberos(KerberosAttr),
    Ldap(LdapAttr),
    Log(LogAttr),
    Mqtt(MqttAttr),
    Network(NetworkAttr),
    Nfs(NfsAttr),
    Ntlm(NtlmAttr),
    Rdp(RdpAttr),
    Smb(SmbAttr),
    Smtp(SmtpAttr),
    Ssh(SshAttr),
    Tls(TlsAttr),
    Window(WindowAttr),
}

impl RawEventKind {
    /// Creates a new `RawEventKind` with the given raw event type and attribute name.
    ///
    /// # Errors
    ///
    /// Returns an error if `RawEventKind` creation fails.
    pub fn from_type_and_attr_name(type_name: &str, attr_name: &str) -> Result<RawEventKind> {
        macro_rules! handle_attr {
            ($attr:ident, $type:ident) => {
                $attr::from_str(attr_name).map(RawEventKind::$type)
            };
        }

        let Ok(raw_event_type) = RawEventType::from_str(type_name) else {
            return Err(anyhow!("unknown raw event type : {type_name}"));
        };
        let parse_result = match raw_event_type {
            RawEventType::Bootp => handle_attr!(BootpAttr, Bootp),
            RawEventType::Conn => handle_attr!(ConnAttr, Conn),
            RawEventType::Dhcp => handle_attr!(DhcpAttr, Dhcp),
            RawEventType::Dns => handle_attr!(DnsAttr, Dns),
            RawEventType::Ftp => handle_attr!(FtpAttr, Ftp),
            RawEventType::Http => handle_attr!(HttpAttr, Http),
            RawEventType::Kerberos => handle_attr!(KerberosAttr, Kerberos),
            RawEventType::Ldap => handle_attr!(LdapAttr, Ldap),
            RawEventType::Log => handle_attr!(LogAttr, Log),
            RawEventType::Mqtt => handle_attr!(MqttAttr, Mqtt),
            RawEventType::Network => handle_attr!(NetworkAttr, Network),
            RawEventType::Nfs => handle_attr!(NfsAttr, Nfs),
            RawEventType::Ntlm => handle_attr!(NtlmAttr, Ntlm),
            RawEventType::Rdp => handle_attr!(RdpAttr, Rdp),
            RawEventType::Smb => handle_attr!(SmbAttr, Smb),
            RawEventType::Smtp => handle_attr!(SmtpAttr, Smtp),
            RawEventType::Ssh => handle_attr!(SshAttr, Ssh),
            RawEventType::Tls => handle_attr!(TlsAttr, Tls),
            RawEventType::Window => handle_attr!(WindowAttr, Window),
        };
        parse_result.map_err(|e| anyhow!("unknown attribute name: {e}"))
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
    #[strum(serialize = "Message Type")]
    MgsType,
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
    #[strum(serialize = "HTTP Method")]
    Method,
    #[strum(serialize = "Host")]
    Host,
    #[strum(serialize = "URI")]
    Uri,
    #[strum(serialize = "Referrer")]
    Referrer,
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
    #[strum(serialize = "Request Filename")]
    OrigFilenames,
    #[strum(serialize = "Request MIME Types")]
    OrigMimeTypes,
    #[strum(serialize = "Response Filename")]
    RespFilenames,
    #[strum(serialize = "Response MIME Types")]
    RespMimeTypes,
    #[strum(serialize = "POST Body")]
    PostBody,
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

#[derive(Debug, EnumString, PartialEq, EnumIter, Display)]
pub enum LogAttr {
    #[strum(serialize = "Content")]
    Content,
}

#[derive(Debug, EnumString, PartialEq, EnumIter, Display)]
pub enum NetworkAttr {
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
    #[strum(serialize = "Content")]
    Content,
}

#[derive(Debug, EnumString, PartialEq, EnumIter, Display)]
pub enum WindowAttr {
    #[strum(serialize = "Service")]
    Service,
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
    #[strum(serialize = "Content")]
    Content,
}

mod tests {

    #[test]
    fn convert_to_protocol_attr_enum() {
        use crate::attribute::{
            BootpAttr, ConnAttr, DhcpAttr, DnsAttr, FtpAttr, HttpAttr, KerberosAttr, LdapAttr,
            LogAttr, MqttAttr, NetworkAttr, NfsAttr, NtlmAttr, RawEventKind, RawEventType, RdpAttr,
            SmbAttr, SmtpAttr, SshAttr, TlsAttr, WindowAttr,
        };

        const INVALID_ATTR_FIELD_NAME: &str = "invalid-attr-field";

        assert_eq!(
            RawEventKind::from_type_and_attr_name(
                &RawEventType::Conn.to_string(),
                &ConnAttr::OrigBytes.to_string()
            )
            .expect("The raw event type and attribute name are always valid."),
            RawEventKind::Conn(ConnAttr::OrigBytes)
        );

        assert_eq!(
            RawEventKind::from_type_and_attr_name(
                &RawEventType::Bootp.to_string(),
                &BootpAttr::Op.to_string()
            )
            .expect("The raw event type and attribute name are always valid."),
            RawEventKind::Bootp(BootpAttr::Op)
        );

        assert_eq!(
            RawEventKind::from_type_and_attr_name(
                &RawEventType::Dhcp.to_string(),
                &DhcpAttr::SubNetMask.to_string()
            )
            .expect("The raw event type and attribute name are always valid."),
            RawEventKind::Dhcp(DhcpAttr::SubNetMask)
        );

        assert_eq!(
            RawEventKind::from_type_and_attr_name(
                &RawEventType::Dns.to_string(),
                &DnsAttr::Query.to_string()
            )
            .expect("The raw event type and attribute name are always valid."),
            RawEventKind::Dns(DnsAttr::Query)
        );

        assert_eq!(
            RawEventKind::from_type_and_attr_name(
                &RawEventType::Ftp.to_string(),
                &FtpAttr::ReplyMsg.to_string()
            )
            .expect("The raw event type and attribute name are always valid."),
            RawEventKind::Ftp(FtpAttr::ReplyMsg)
        );

        assert_eq!(
            RawEventKind::from_type_and_attr_name(
                &RawEventType::Http.to_string(),
                &HttpAttr::UserAgent.to_string()
            )
            .expect("The raw event type and attribute name are always valid."),
            RawEventKind::Http(HttpAttr::UserAgent)
        );

        assert_eq!(
            RawEventKind::from_type_and_attr_name(
                &RawEventType::Kerberos.to_string(),
                &KerberosAttr::CnameType.to_string()
            )
            .expect("The raw event type and attribute name are always valid."),
            RawEventKind::Kerberos(KerberosAttr::CnameType)
        );

        assert_eq!(
            RawEventKind::from_type_and_attr_name(
                &RawEventType::Ldap.to_string(),
                &LdapAttr::DiagnosticMessage.to_string()
            )
            .expect("The raw event type and attribute name are always valid."),
            RawEventKind::Ldap(LdapAttr::DiagnosticMessage)
        );

        assert_eq!(
            RawEventKind::from_type_and_attr_name(
                &RawEventType::Log.to_string(),
                &LogAttr::Content.to_string()
            )
            .expect("The raw event type and attribute name are always valid."),
            RawEventKind::Log(LogAttr::Content)
        );

        assert_eq!(
            RawEventKind::from_type_and_attr_name(
                &RawEventType::Mqtt.to_string(),
                &MqttAttr::SubackReason.to_string()
            )
            .expect("The raw event type and attribute name are always valid."),
            RawEventKind::Mqtt(MqttAttr::SubackReason)
        );

        assert_eq!(
            RawEventKind::from_type_and_attr_name(
                &RawEventType::Nfs.to_string(),
                &NfsAttr::WriteFiles.to_string()
            )
            .expect("The raw event type and attribute name are always valid."),
            RawEventKind::Nfs(NfsAttr::WriteFiles)
        );

        assert_eq!(
            RawEventKind::from_type_and_attr_name(
                &RawEventType::Ntlm.to_string(),
                &NtlmAttr::Domainname.to_string()
            )
            .expect("The raw event type and attribute name are always valid."),
            RawEventKind::Ntlm(NtlmAttr::Domainname)
        );

        assert_eq!(
            RawEventKind::from_type_and_attr_name(
                &RawEventType::Rdp.to_string(),
                &RdpAttr::Cookie.to_string()
            )
            .expect("The raw event type and attribute name are always valid."),
            RawEventKind::Rdp(RdpAttr::Cookie)
        );

        assert_eq!(
            RawEventKind::from_type_and_attr_name(
                &RawEventType::Smb.to_string(),
                &SmbAttr::ResourceType.to_string()
            )
            .expect("The raw event type and attribute name are always valid."),
            RawEventKind::Smb(SmbAttr::ResourceType)
        );

        assert_eq!(
            RawEventKind::from_type_and_attr_name(
                &RawEventType::Smtp.to_string(),
                &SmtpAttr::MailFrom.to_string()
            )
            .expect("The raw event type and attribute name are always valid."),
            RawEventKind::Smtp(SmtpAttr::MailFrom)
        );

        assert_eq!(
            RawEventKind::from_type_and_attr_name(
                &RawEventType::Ssh.to_string(),
                &SshAttr::CipherAlg.to_string()
            )
            .expect("The raw event type and attribute name are always valid."),
            RawEventKind::Ssh(SshAttr::CipherAlg)
        );

        assert_eq!(
            RawEventKind::from_type_and_attr_name(
                &RawEventType::Tls.to_string(),
                &TlsAttr::Ja3.to_string()
            )
            .expect("The raw event type and attribute name are always valid."),
            RawEventKind::Tls(TlsAttr::Ja3)
        );

        assert_eq!(
            RawEventKind::from_type_and_attr_name(
                &RawEventType::Window.to_string(),
                &WindowAttr::AgentId.to_string()
            )
            .expect("The raw event type and attribute name are always valid."),
            RawEventKind::Window(WindowAttr::AgentId)
        );

        assert_eq!(
            RawEventKind::from_type_and_attr_name(
                &RawEventType::Network.to_string(),
                &NetworkAttr::Content.to_string()
            )
            .expect("The raw event type and attribute name are always valid."),
            RawEventKind::Network(NetworkAttr::Content)
        );

        assert!(RawEventKind::from_type_and_attr_name(
            &RawEventType::Conn.to_string(),
            INVALID_ATTR_FIELD_NAME
        )
        .is_err());
    }
}
