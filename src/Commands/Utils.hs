module Command.Utils
where

data CommandRetCode = Exit | Error | Continue

type CommandConstraint m = (Cache m, MonadIO m, KatipContext m, MonadException m, MonadState MyState m)

