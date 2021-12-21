{-|
Module      : Net.Mptcp
Description : Implementation of mptcp netlink path manager
Maintainer  : matt
Stability   : testing
Portability : Linux

OverloadedStrings allows Aeson to convert
-}
{-# LANGUAGE DeriveGeneric, CPP #-}
{-# LANGUAGE OverloadedStrings #-}
module Net.Mptcp (
  -- * Types
  MptcpConnection (..)
  , MptcpPacket
  , MptcpSocket (..)
  -- , MptcpToken
  , mptcpConnAddSubflow
  , mptcpConnRemoveSubflow
  , showMptcpSocket
  -- , remoteIdFromAttributes
)
where

-- mptcp-pm
import Net.Mptcp.Netlink
import Net.Mptcp.Types
import Net.Tcp
import Net.SockDiag ()

-- hackage
-- import Control.Exception (assert)

-- import qualified Data.Map as Map
-- import Data.Word (Word16, Word32, Word8)
-- import System.Linux.Netlink hiding (makeSocket)
-- import System.Linux.Netlink (query, Packet(..))
-- import System.Linux.Netlink.GeNetlink.Control
-- import Data.ByteString (ByteString)
-- import Data.Maybe (fromJust)

-- import Data.Serialize.Get
-- import 

import Control.Concurrent ()
import Control.Monad.Trans.State ()
import Data.List ()
import qualified Data.Set as Set
import Data.Word (Word8)
-- import Debug.Trace
-- import System.Linux.Netlink.Constants





-- |Adds a subflow to the connection
-- TODO compose with mptcpConnAddLocalId
mptcpConnAddSubflow :: MptcpConnection -> TcpConnection -> MptcpConnection
mptcpConnAddSubflow mptcpConn sf =
  -- trace ("Adding subflow" ++ show sf)
    mptcpConnAddLocalId
        (mptcpConnAddRemoteId
            (mptcpConn { subflows = Set.insert sf (subflows mptcpConn) })
            (remoteId sf)
        )
        (localId sf)

    -- , localIds = Set.insert (localId sf) (localIds mptcpConn)
    -- , remoteIds = Set.insert (remoteId sf) (remoteIds mptcpConn)
  -- }


-- |Add local id
mptcpConnAddLocalId :: MptcpConnection
                       -> Word8 -- ^Local id to add
                       -> MptcpConnection
mptcpConnAddLocalId con locId = con { localIds = Set.insert (locId) (localIds con) }


-- |Add remote id
mptcpConnAddRemoteId :: MptcpConnection
                       -> Word8 -- ^Remote id to add
                       -> MptcpConnection
mptcpConnAddRemoteId con remId = con { localIds = Set.insert (remId) (remoteIds con) }

-- |Remove subflow from an MPTCP connection
mptcpConnRemoveSubflow :: MptcpConnection -> TcpConnection -> MptcpConnection
mptcpConnRemoveSubflow con sf = con {
  subflows = Set.delete sf (subflows con)
  -- TODO remove associated local/remote Id ?
}



-- doDumpLoop :: MyState -> IO MyState
-- doDumpLoop myState = do
--     let (MptcpSocket simpleSock fid) = socket myState
--     results <- recvOne' simpleSock ::  IO [Either String MptcpPacket]
--     -- TODO retrieve packets
--     mapM_ (inspectResult myState) results
--     newState <- doDumpLoop myState
--     return newState


-- data MptcpAttributes = MptcpAttributes {
--     connToken :: Word32
--     , localLocatorID :: Maybe Word8
--     , remoteLocatorID :: Maybe Word8
--     , family :: Word16 -- Remove ?
--     -- |Pointer to the Attributes map used to build this struct. This is purely
--     -- |for forward compat, please file a feature report if you have to use this.
--     , staSelf       :: Attributes
-- } deriving (Show, Eq, Read)

-- Wouldn't it be easier to work with ?
-- data MptcpEvent = NewConnection {
-- }
