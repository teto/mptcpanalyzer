{-|
Module      : System.Linux.Netlink.Routing
Description : Implementation of mptcp netlink path manager
Maintainer  : matt
Stability   : testing
Portability : Linux

-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
module Netlink.Routing (
  queryAddrs
)
where
import System.Linux.Netlink.Constants as NLC
-- import System.Linux.Netlink.GeNetlink as GENL

import System.Linux.Netlink as NL
import Data.Bits ((.|.))

-- import System.Linux.Netlink.GeNetlink.Control
import qualified System.Linux.Netlink.Route as NLR
-- import qualified System.Linux.Netlink.Simple as NLS

-- should have this running in parallel
queryAddrs :: NLR.RoutePacket
queryAddrs = NL.Packet
    (NL.Header NLC.eRTM_GETADDR (NLC.fNLM_F_ROOT .|. NLC.fNLM_F_MATCH .|. NLC.fNLM_F_REQUEST) 0 0)
    (NLR.NAddrMsg 0 0 0 0 0)
    mempty
