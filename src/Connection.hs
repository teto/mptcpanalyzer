module Connection
where


newtype Score = Int

instance Eq TcpConnection where

    -- (==) :: a -> a -> Bool infix 4
    (==) con1 con2 =


compareConnections :: TcpConnection -> TcpConnection -> Score
compareConnections con1 con2 =
        score = 0
        case con1 == con2 of
          True -> 100
          False -> ipSimilarity + portSimilarity

        score += 10 if self.tcpserver_ip == other.tcpserver_ip else 0
        score += 10 if self.tcpclient_ip == other.tcpclient_ip else 0
        score += 10 if self.client_port == other.client_port else 0
        score += 10 if self.server_port == other.server_port else 0

        return score
        where
            srcIp con1 == srcIp con2

