module Main

import Text.Crypt

single : IO ()
single = do
  salt <- gensalt "$y$" 8
  putStrLn "\n\nSalt generated: \{salt}"
  putStrLn "Check salt: \{show $ checksalt salt}"
  let phrase = "my_very_secret_passphrase"
      key    = crypt salt phrase
  putStrLn "Encrypted passphrase: \{key}"
  putStrLn "Crypt check result: \{show $ cryptcheck key phrase}"

run : Nat -> PrimIO ()
run Z w = MkIORes () w
run (S n) w =
  let MkIORes () w2 := toPrim single w
   in run n w2

main : IO ()
main = fromPrim $ run 10
