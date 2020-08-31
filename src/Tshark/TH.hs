{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell            #-}
module Tshark.TH
where

import qualified Data.Text as T
import Language.Haskell.TH
import Net.IP
import Data.Word (Word8, Word16, Word32, Word64)
-- import Language.Haskell.TH.Syntax

data TsharkFieldDesc = TsharkFieldDesc {
        fullname :: T.Text
        -- ^Test
        , colType :: Q Type
        -- , colType :: TsharkField
        -- ^How to reference it in plot
        , label :: Maybe String
        -- ^Wether to take into account this field when creating a hash of a packet
        , hash :: Bool
    }
    -- deriving (Read, Generic)

-- baseFields :: [(String, TsharkFieldDesc)]
-- type MyColumns =  SkillLevel ': NumericalAnswer ': CommonColumns
baseFields :: [(String, TsharkFieldDesc)]
baseFields = [
    -- 'UInt64'
    -- " "interface"
    ("packetid", TsharkFieldDesc "frame.number" [t|Word64|] Nothing False),
    ("ifname", TsharkFieldDesc "frame.interface_name" [t|String|] Nothing False),
    ("abstime", TsharkFieldDesc "frame.time_epoch" [t|String|] Nothing False),
    ("ipsrc", TsharkFieldDesc "_ws.col.ipsrc" [t|IP|] (Just "source ip") False),
    ("ipdst", TsharkFieldDesc "_ws.col.ipdst" [t|IP|] Nothing False),
    ("tcpstream", TsharkFieldDesc "tcp.stream" [t|Int|] Nothing False),
    -- TODO use Word32 instead
    ("sport", TsharkFieldDesc "tcp.srcport" [t|Word16|] Nothing False),
    ("dport", TsharkFieldDesc "tcp.dstport" [t|Word16|] Nothing False),
    -- TODO read as a list
    ("tcpflags", TsharkFieldDesc "tcp.dstport" [t|String|] Nothing False),
    ("tcpoptionkind", TsharkFieldDesc "tcp.dstport" [t|Word32|] Nothing False),
    ("tcpseq", TsharkFieldDesc "tcp.seq" [t|Word32|] (Just "Sequence number") False),
    ("tcpack", TsharkFieldDesc "tcp.ack" [t|Word32|] (Just "Acknowledgement") False)
    ]


getTypes :: [(String, TsharkFieldDesc)] -> [Q Type]
getTypes = map (\(_, x) -> colType x)
