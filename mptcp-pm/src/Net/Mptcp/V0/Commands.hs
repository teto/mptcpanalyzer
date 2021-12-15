
-- sport/backup/intf are optional
newSubflowPkt :: MptcpSocket -> MptcpConnection -> TcpConnection -> MptcpPacket
newSubflowPkt (MptcpSocket _ fid) mptcpCon sf = let
    _cmd = MPTCP_CMD_SUB_CREATE
    attrs = connectionAttrs mptcpCon ++ subflowAttrs sf
    pkt = genMptcpRequest fid MPTCP_CMD_SUB_CREATE False attrs
  in
    assert (hasFamily attrs) pkt

