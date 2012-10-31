module std.windows.ini;

import std.stdio : File;
import std.string;
import std.conv : to;
import std.exception;

struct INI
{
	private File 			_file;
	private string 			_lastSection;
	Section[]				sections;
	
	@property string fileName(in string value)
	{
		if(value == _file.name)
			return value;
		
		this._file.close();
		this._file = File(value, "w");
		
		return value;
	}
	
	alias sections this;
	
	this(in string fileName)
	{
		this._file = File(fileName, "rw");
		
		foreach(rawLine; this._file.byLine())
			appendLine(to!string(rawLine));
	}
	
	private void appendLine(in string rawLine)
	{
		auto line = stripLeft(rawLine);
		if(line.length && line[0] == '[')
			appendSectionLine(rawLine);
		else
			appendPropertyLine(rawLine);
	}
	
	private void appendSectionLine(in string rawLine)
	{
		sections ~= Section(rawLine, true);
	}
	
	private void appendPropertyLine(in string rawLine)
	{
		if(!sections.length)
			sections ~= Section();
		
		sections[$-1].add(rawLine);
	}
	
	auto get(in string name)
	{
		foreach(k, s; sections)
			if(s.name == name)
				return &sections[k];
		return null;
	}
	
	auto add(in string name)
	{
		sections ~= Section(name);
		return &sections[$-1];
	}
	
	void save()
	{
		enforce(_file.isOpen());
		_file.write(this.toString());
	}
	
	string toString() const
	{
		string[] output;
		foreach(s; sections)
			output ~= s.toString();
		output ~= "";
		return output.join(std.ascii.newline);
	}
	
	unittest
	{
		assertThrown(new INI("/home/mike/failure"));
		
		INI t = INI("test1.ini");
		auto mike = t.get("Mike");
		mike.set("awesome", "yes");
		mike.set("age", "20");
		
		auto luuk = t.get("Luuk");
		luuk.set("awesome", "epic");
		
		auto semm = t.add("Semm");
		semm.set("age", "8");
		semm.set("awesome", "yes");
		
		t.fileName = "test2.ini";
		t.save();
		
		
		INI n = INI();
		auto one = n.add("Movies 1");
		one.add("comment", "");
		one.add("path", "/media/Media/My Videos");
		one.add("browseable", "yes");
		one.add("read only", "yes");
		one.add("guest ok", "yes");
		one.add("");
		
		n.fileName = "test3.ini";
		n.save();
	}
}

private struct Section
{
	private	string			_format;
	private	string			_name;
	Line[]					lines;
	string					defaultLineFormat = "%s = %s";
	bool					lineFormatApplyAlways;
	
	@property string name() { return _name; }
	
	alias lines this;
	
	this(in string s, bool needsProcessing = false)
	{
		if(needsProcessing)
			processLine(s);
		else
			setName(s);
	}
	
	private void processLine(in string line)
	{
		if(!line.length)
			return;
		
		auto i = indexOf(line, "[");
		enforce(i != -1);
		
		auto j = indexOf(line, "]");
		enforce(j != -1);
		
		this._name = strip(line[i+1 .. j]);
		enforce(this._name.length);
		auto nameStart = indexOf(line[i+1 .. j], this._name[0]) + i + 1;
		this._format = line[0 .. nameStart] ~ "%s" ~ line[nameStart + this._name.length .. $];
	}
	
	private void setName(in string name)
	{
		enforce(name.length);
		
		this._name = name;
		this._format = "[%s]";
	}
	
	auto get(in string key)
	{
		foreach(k, l; lines)
			if(l.key == key)
				return &lines[k];
		return null;
	}
	
	auto add(in string line)
	{
		lines ~= Line(line);
		return &lines[$-1];
	}
	
	auto add(in string key, in string value)
	{
		lines ~= Line(key, value);
		return &lines[$-1];
	}
	
	auto set(in string key, in string value)
	{
		auto line = get(key);
		if(!line)
			return add(key, value);
		line.value = value;
		return line;
	}
	
	string toString() const
	{
		string[] output;
		if(_name.length)
			output ~= format(_format, _name);
		
		foreach(l; lines)
			output ~= l.toString();
		
		return output.join(std.ascii.newline);
	}
}

private struct Line
{
	private	string			_format;
	private string 			_key;
	string 					value;
	
	@property string key() { return _key; }
	
	@disable this();
	
	this(in string line)
	{
		if(isMeaninglessLine(line))
		{
			_format = line;
			return;
		}
		
		auto i = indexOf(line, "=");
		enforce(i > 0);
		
		this._key = strip(line[0 .. i]);
		enforce(this._key.length);
		this.value = strip(line[i+1 .. $]);
		
		auto keyStart = indexOf(line[0 .. i], this._key[0]);
		auto valueStart = (this.value.length ? indexOf(line[i+1 .. $], this.value[0]) : 0) + i + 1;
		this._format = line[0 .. keyStart]
					 ~ "%s"
					 ~ line[keyStart + this._key.length .. valueStart]
					 ~ "%s" ~ line[valueStart + this.value.length .. $];
	}
	
	this(in string key, in string value, in string format = "%s = %s")
	{
		this._key = key;
		enforce(this._key.length);
		this.value = value;
		this._format = format;
	}
	
	private bool isMeaninglessLine(in string line)
	{
		auto strippedLine = stripLeft(line);
		return !strippedLine.length || strippedLine[0] == ';' || strippedLine[0] == '#';
	}
	
	string toString() const
	{
		return _key.length ? format(_format, _key, value) : _format;
	}
}
