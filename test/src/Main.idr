module Main

import Text.Crypt
import Data.DPair

single : IO ()
single = do
  Just salt <- refineSalt <$> gensalt YesCrypt 10
    | Nothing => putStrLn "Invalid salt generated."
  putStrLn "\n\nSalt generated: \{fst salt}"

  Just phrase <- pure (refinePassphrase "my_very_secret_passphrase")
    | Nothing => putStrLn "Invalid pass phrase."

  Just hash <- pure (refineHash $ cryptWithSalt salt phrase)
    | Nothing => putStrLn "Invalid hash generated."
  putStrLn "Encrypted passphrase: \{fst hash}"
  putStrLn "Crypt check result: \{show $ cryptcheck hash phrase}"
 
run : Nat -> PrimIO ()
run Z w = MkIORes () w
run (S n) w =
  let MkIORes () w2 := toPrim single w
   in run n w2

main : IO ()
main = fromPrim $ run 10
