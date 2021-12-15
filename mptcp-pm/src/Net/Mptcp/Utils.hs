module Net.Mptcp.Utils 
where

import Data.ByteString
import Net.Mptcp.Types
import Data.Serialize.Get

-- | TODO change / return Either
readToken :: ByteString -> Either String MptcpToken
readToken val = runGet getWord32host val

