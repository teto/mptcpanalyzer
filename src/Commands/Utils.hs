{-# LANGUAGE ConstraintKinds #-}
{-# LANGUAGE FlexibleContexts #-}
module Commands.Utils
where

-- import Katip
-- import Control.Monad.State (MonadState)
-- import Control.Monad.Trans (MonadIO)
-- import System.Console.Haskeline.MonadException
import Utils
import Data.Text
import Polysemy
import Mptcp.Logging
import Mptcp.Cache

import qualified Polysemy.State as P

data RetCode = Exit | Error Text | Continue

-- MonadException m,
-- type CommandConstraint m = (Cache m, MonadIO m, KatipContext m, MonadState MyState m)
-- be able to conncatenate EffectRow
type DefaultConstraints = [Log, P.State MyState, Cache, Embed IO]

-- TODO because of commands :: HM.Map String (CommandCb m)
-- all commands need to have the same type

type CommandConstraint m = Members [Log, P.State MyState, Cache ] m

-- shouldnot modify state
type CommandCb m = CommandConstraint m => [String] -> Sem m RetCode
