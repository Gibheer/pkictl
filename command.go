package main

// handle the command infrastructure

import (
  "fmt"
  "flag"
  "os"
)

type (
  Command struct {
    Use   string // command name (used for matching)
    Short string // a short description  to display
    Long  string // a long help text
    Example string // an example string
    Run   func(*Command, []string)

    flagSet *flag.FlagSet
    commands []*Command
  }
)

func (c *Command) AddCommand(cmds... *Command) {
  res := c.commands
  for _, cmd := range cmds {
    res = append(res, cmd)
  }
  c.commands = res
}

func (c *Command) eval(args []string) error {
  var name string = ""
  var rest []string = []string{}

  if len(args) > 0 {
    name = args[0]
  }
  if len(args) > 1 {
    rest = args[1:]
  }

  if name == "help" {
    c.Help(rest)
    return nil
  }

  for _, cmd := range c.commands {
    if cmd.Use == name {
      return cmd.eval(rest)
    }
  }
  if err := c.Flags().Parse(rest); err != nil { return err }
  if c.Run != nil {
    c.Run(c, rest)
  } else {
    c.Help(rest)
  }
  return nil
}

func (c *Command) Execute() error {
  return c.eval(os.Args[1:])
}

func (c *Command) Flags() *flag.FlagSet {
  if c.flagSet == nil { c.flagSet = flag.NewFlagSet(c.Use, flag.ContinueOnError) }
  return c.flagSet
}

func (c *Command) Help(args []string) {
  if len(args) > 0 {
    for _, cmd := range c.commands {
      if args[0] == cmd.Use {
        cmd.Help([]string{})
        return
      }
    }
  }
  if c.Long != "" { fmt.Println(c.Long, "\n") }
  c.Usage()
}

func (c *Command) Usage() {
  usage := ""
  if c.Use != "" {
    usage = usage + " " + c.Use
  }
  if len(c.commands) > 0 {
    usage = usage + " command"
  }
  if c.flagSet != nil {
    usage = usage + " [flags]"
  }
  fmt.Printf("Usage: %s%s\n", os.Args[0], usage)

  if len(c.commands) > 0 {
    fmt.Printf("\nwhere command is one of:\n")
    for _, cmd := range c.commands {
      fmt.Printf("\t%s\t\t%s\n", cmd.Use, cmd.Short)
    }
  }
  if c.flagSet != nil {
    fmt.Printf("\nwhere flags is any of:\n")
    c.Flags().SetOutput(os.Stdout)
    c.Flags().PrintDefaults()
  }
  if c.Example != "" {
    fmt.Println("\nexample:")
    fmt.Printf("\t%s\n", c.Example)
  }
}
