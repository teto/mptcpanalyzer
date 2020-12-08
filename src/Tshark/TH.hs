{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TemplateHaskell            #-}
module Tshark.TH
where

import qualified Data.Text as T
import Language.Haskell.TH
-- import Net.IP
import Data.Word (Word16, Word32, Word64)
-- import Language.Haskell.TH.Syntax
import Data.Vinyl ()

-- for ( (:->)())
import Frames.Col ()
-- for symbol
-- import GHC.Types

data TsharkFieldDesc = TsharkFieldDesc {
        fullname :: T.Text
        -- ^Test
        , colType :: Q Type
        -- ^How to reference it in plot
        , label :: Maybe T.Text
        -- ^Wether to take into account this field when creating a hash of a packet
        , hash :: Bool
    }
    -- deriving (Read, Generic)

-- genRow :: [ TsharkFieldDesc ] -> Q Type
-- genRow fields = rowTy
--   where f field = fullname field :-> colType field
--         rowTy = TySynD (mkName rowTypeName) [] (recDec colTypes)

-- mkColSynDec

-- baseFields :: [(String, TsharkFieldDesc)]
-- type MyColumns =  SkillLevel ': NumericalAnswer ': CommonColumns
-- frame.number,frame.interface_name,frame.time_epoch,_ws.col.ipsrc,_ws.col.ipdst,ip.src_host,ip.dst_host,tcp.stream,tcp.srcport,tcp.dstport,tcp.flags,tcp.option_kind,tcp.seq,tcp.len,tcp.ack
baseFields :: [(String, TsharkFieldDesc)]
baseFields = [
    ("packetid", TsharkFieldDesc "frame.number" [t|Word64|] Nothing False)
    -- ("packetid", TsharkFieldDesc "frame.number" ("packetid" :-> Word64) Nothing False)
    -- ("ifname", TsharkFieldDesc "frame.interface_name" [t|String|] Nothing False),
    -- ("abstime", TsharkFieldDesc "frame.time_epoch" [t|String|] Nothing False),
    -- ("ipsrc", TsharkFieldDesc "_ws.col.ipsrc" [t|IP|] (Just "source ip") False),
    -- ("ipdst", TsharkFieldDesc "_ws.col.ipdst" [t|IP|] Nothing False),
    , ("tcpstream", TsharkFieldDesc "tcp.stream" [t|Word32|] Nothing False)
    -- -- TODO use Word32 instead
    , ("sport", TsharkFieldDesc "tcp.srcport" [t|Word16|] Nothing False)
    , ("dport", TsharkFieldDesc "tcp.dstport" [t|Word16|] Nothing False)
    -- -- TODO read as a list
    -- ("tcpflags", TsharkFieldDesc "tcp.dstport" [t|String|] Nothing False),
    -- ("tcpoptionkind", TsharkFieldDesc "tcp.dstport" [t|Word32|] Nothing False),
    -- ("tcpseq", TsharkFieldDesc "tcp.seq" [t|Word32|] (Just "Sequence number") False),
    -- ("tcpack", TsharkFieldDesc "tcp.ack" [t|Word32|] (Just "Acknowledgement") False)
    ]

-- "user id" :-> Int
getTypes :: [(String, TsharkFieldDesc)] -> [Q Type]
getTypes = map (\(_, x) -> colType x)
