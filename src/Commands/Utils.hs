{-# LANGUAGE ConstraintKinds #-}
{-# LANGUAGE FlexibleContexts #-}
module Commands.Utils
where

import Katip
import Cache
import Control.Monad.State (MonadState)
import Control.Monad.Trans (MonadIO)
-- import System.Console.Haskeline.MonadException
import Utils
import Data.Text

data RetCode = Exit | Error Text | Continue

-- MonadException m,
type CommandConstraint m = (Cache m, MonadIO m, KatipContext m, MonadState MyState m)

type CommandCb m = [String] -> m RetCode
