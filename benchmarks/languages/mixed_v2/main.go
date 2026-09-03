package main
import ("os"; "os/exec")
func main() { exec.Command(os.Getenv("CMD")).Run() }
