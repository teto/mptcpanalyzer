{-# LANGUAGE TemplateHaskell            #-}
module Tshark.TH
where

-- baseFields :: [(String, TsharkFieldDesc)]
-- type MyColumns =  SkillLevel ': NumericalAnswer ': CommonColumns
baseFields :: [(String, TsharkFieldDesc)]
baseFields = [
    -- 'UInt64'
    -- SFullName "frame.number" :& (SName "packetid") :&  False False
    -- " "interface"
    ("packetid", TsharkFieldDesc "frame.interface_name" [t|String|] Nothing False),
    ("ipsrc", TsharkFieldDesc "_ws.col.ipsrc" [t|IP|](Just "source ip") False),
    ("ipdst", TsharkFieldDesc "_ws.col.ipdst" [t|IP|] Nothing False),
    -- Field "ip.src_host" "ipsrc_host" str False False,
    -- Field "ip.dst_host" "ipdst_host" str False False,
    ("tcpstream", TsharkFieldDesc "tcp.stream" [t|Int|] Nothing False),
    -- TODO use Word32 instead
    ("sport", TsharkFieldDesc "tcp.srcport" [t|Int|] Nothing False)
    -- Field "tcp.dstport" "dport" 'UInt16' False False,
    -- Field "tcp.dstport" "dport" 'UInt16' False False,
    -- Field "frame.time_relative" "reltime" str "Relative time" False False
    -- Field "frame.time_epoch" "abstime" str "seconds+Nanoseconds time since epoch" False False
    ]


getTypes :: [Tshark] -> [Q Type]
getTypes = do 
  [| map (\x -> colType x) baseFields |]
