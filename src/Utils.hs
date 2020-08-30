{-# LANGUAGE TemplateHaskell            #-}
module Utils
where

import Pcap
import Katip
-- import Lens.Micro
import Control.Lens
import Options.Applicative

-- |Helper to pass information across functions
data MyState = MyState {
  _cacheFolder :: FilePath

  , _msKNamespace :: Namespace    -- ^Katip namespace
  , _msLogEnv :: LogEnv     -- ^ Katip log env
  , _msKContext   :: LogContexts

  , _loadedFile   :: Maybe PcapFrame  -- ^ cached loaded pcap
  , _prompt   :: String  -- ^ cached loaded pcap
}

makeLenses ''MyState


defaultParserPrefs :: ParserPrefs
defaultParserPrefs = defaultPrefs

