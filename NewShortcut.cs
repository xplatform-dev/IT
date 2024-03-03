

[Cmdlet(VerbsCommon.New,"ValidPath")]
class NewShortcutCmdlet : PSCmdlet
{
  [Parameter(
    Mandatory = true,
    
  )]
  public string localPath;

  [Parameter(
    Mandatory = true,
  )]
  public string shortcutName;

  [Parameter(
    Mandatory = true,
  )]
  public URI targetPath;

  [Parameter(
  )]
  public int windowStyle;

  [Parameter(
  )]
  public string description;

  Parameter(
  )]
  public string[] arguments;

  [Parameters(
  )]
  public URI iconLocation;

  [Parameter(
  )]
  public string WorkingDirectory;

  private WshShellClass wsh;

  protected override void BeginProcessing() {
    wsh = new WshShellClass();
  }

  protected override void ProcessRecord() {
    if (!(shortcutName.EndsWith(".lnk"))
    {
      shortcutName = shortcutName + ".lnk";
    }

    if (!Directory.Exists(localPath))
    {
      throw new Directory
    }
    
    IWshRuntimeLibrary.IWshShortcut shortcut = wsh.CreateShortcut(
      Environment.GetFolderPath(localPath + 
  }

  
}
