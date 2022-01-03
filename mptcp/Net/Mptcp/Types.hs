module Net.Mptcp.Types
where

import qualified Data.Set as Set
import Data.Text (Text)
import qualified Data.Text as TS
import Data.Word (Word16, Word32, Word64, Word8)
import Net.IP
import Net.Tcp

-- type MptcpSendKey = Word64

-- For now... for convenience only
-- type MptcpSubflow = TcpConnection

-- | Overrides the MptcpConnection from
-- mptcp-pm (for backwards compatibility:
-- remove it later on)

