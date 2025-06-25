package system

func makeQualified(name string) string {
	if len(name) < 1 {
		return "."
	}

	if name[len(name)-1] != '.' {
		return name + "."
	}

	return name
}
