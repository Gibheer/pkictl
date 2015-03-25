// Handler to make management of subcommands easier.
package main

import (
	"flag"
	"fmt"
	"os"
)

type (
	Command struct {
		Use     string                   // command name (used for matching)
		Short   string                   // a short description  to display
		Long    string                   // a long help text
		Example string                   // an example string
		Run     func(*Command, []string) // the command to run

		flagSet  *flag.FlagSet // internal flagset with all flags
		commands []*Command    // the list of subcommands
	}
)

// This function adds a new sub command.
func (c *Command) AddCommand(cmds ...*Command) {
	res := c.commands
	for _, cmd := range cmds {
		res = append(res, cmd)
	}
	c.commands = res
}

// Evaluate the arguments and call either the subcommand or parse it as flags.
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
	if err := c.Flags().Parse(args); err != nil {
		return err
	}
	if c.Run != nil {
		c.Run(c, rest)
	} else {
		c.Help(rest)
	}
	return nil
}

// Execute the command. It will fetch os.Args[1:] itself.
func (c *Command) Execute() error {
	return c.eval(os.Args[1:])
}

// Return the flagset currently in use.
func (c *Command) Flags() *flag.FlagSet {
	if c.flagSet == nil {
		c.flagSet = flag.NewFlagSet(c.Use, flag.ContinueOnError)
	}
	return c.flagSet
}

// Print the help for the current command or a subcommand.
func (c *Command) Help(args []string) {
	if len(args) > 0 {
		for _, cmd := range c.commands {
			if args[0] == cmd.Use {
				cmd.Help([]string{})
				return
			}
		}
	}
	if c.Long != "" {
		fmt.Println(c.Long, "\n")
	}
	c.Usage()
}

// Print the usage information.
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
