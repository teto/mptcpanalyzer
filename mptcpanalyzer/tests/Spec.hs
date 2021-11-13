{-# OPTIONS_GHC -F -pgmF hspec-discover #-}
-- https://hspec.github.io/hspec-discover.html
import Test.Hspec.Runner
import Test.Hspec.Formatters
import qualified Spec

main :: IO ()
main = hspecWith defaultConfig {configFormatter = Just progress} Spec.spec
