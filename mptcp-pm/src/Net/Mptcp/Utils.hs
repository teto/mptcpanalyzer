module Net.Mptcp.Utils 
where

import Data.Word
import Data.ByteString
import Net.Mptcp.Types
import Data.Serialize.Get

-- | TODO change / return Either
readToken :: ByteString -> Either String MptcpToken
readToken val = runGet getWord32host val

getPort :: ByteString -> Word16
getPort val =
  case (runGet getWord16host val) of
    Left _     -> 0
    Right port -> port






-- LocId => Word8
readLocId :: Maybe ByteString -> LocId
readLocId maybeVal = case maybeVal of
  Nothing -> error "Missing locator id"
  Just val -> case runGet getWord8 val of
    -- TODO generate an error here !
    Left _      -> error "Could not get locId !!"
    Right locId -> locId
  -- runGet getWord8 val

