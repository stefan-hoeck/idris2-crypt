module Main

import Text.Crypt

main : IO ()
main = gensalt "$y$" 11 >>= putStrLn
