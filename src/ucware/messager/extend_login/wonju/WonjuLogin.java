package ucware.messager.extend_login.wonju;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Properties;

import org.apache.commons.codec.CharEncoding;
import org.apache.commons.codec.binary.Base64;
import org.apache.log4j.Logger;

import oracle.jdbc.pool.OracleDataSource;
import ucware.messager.common.config.AbstractConfig;
import ucware.messager.common.repository.AbstractRepositoryFactory;
import ucware.messager.common.repository.user.AbstractUserInfo;
import ucware.messager.common.repository.user.AbstractUserRepository;
import ucware.messager.server.customer.extend.ExtendCertify;
import ucware.messager.server.customer.extend.LoginType;

public class WonjuLogin extends ExtendCertify {
	
	class OracalConnectionPool {
		private OracleDataSource poolDataSource;
		
		OracalConnectionPool(String hostName, int port, String dbUserName, String dbUserPassword, String dbName) throws SQLException{
			poolDataSource = new OracleDataSource();
			String url = "jdbc:oracle:thin:@" + hostName + ":" + port + ":" + dbName;
			
//			logger.debug("oracle url :"+url);
			
			poolDataSource.setURL(url);
			poolDataSource.setUser(dbUserName);
			poolDataSource.setPassword(dbUserPassword);
		}
		
		Connection getConnection() throws SQLException{
			Connection connection = null;
			synchronized(this){
				connection = poolDataSource.getConnection();
			}
			return connection;
		}
	}
	
	private static Logger logger = Logger.getLogger(AbstractConfig.logName);
	
	private static final String iniFilePath = "../extend_lib/wonju/login.ini";
	
	private String dbHost = null;
	private int dbPort = 0;
	private String dbUserName = null;
	private String dbUserPassword = null;
	private String dbName = null;
	private String sql = null;
	
	private boolean isInit = false;
	
	private OracalConnectionPool connectionPool;

	@Override
	public LoginType loginCheck(String userID, String password, String userField1, String userField2, String userField3, String userField4, String userField5) throws InterruptedException {
//		logger.debug("call loginCheck");
		if(!isInit){
			init();
			try {
				connectionPool = new OracalConnectionPool(dbHost, dbPort, dbUserName, dbUserPassword, dbName);
			} catch (SQLException e) {
				logger.error(e);
			}
		}else{}
		AbstractUserRepository userRepository = AbstractRepositoryFactory.getRepositoryFactory().getUserRepository();
		
//		logger.debug("userRepository:"+userRepository);
		
		AbstractUserInfo userInfo = userRepository.getUserInfo(userID);
		
		if(userInfo == null){
			
//			logger.debug("userInfo is null");
			
			return LoginType.noUserID;
		}else{
			Connection connection = null;
			PreparedStatement pst = null;
			ResultSet resultSet = null;
			try {
				connection = connectionPool.getConnection();
				if(connection != null){
					String userSelectSQL = sql.replace("(%USER_ID%)", "'" + userID + "'").replace("(%USER_PASSWORD%)", " ? ");
					
//					logger.debug("userSelectSQL :" + userSelectSQL);
					
					
//					logger.debug("input password : " + password);
					password = encryptSHA256(password);
//					logger.debug("sha256_base64 password : " + password);
					try {
						pst = connection.prepareStatement(userSelectSQL);
						pst.setString(1, password);
						resultSet = pst.executeQuery();
						if(resultSet.next()){
							return LoginType.success;
						}else{
							return LoginType.wrongPassword;
						}
					} catch (SQLException e) {
						logger.error(e);
						return LoginType.notDBConnect;
					}
				}else{
					return LoginType.notDBConnect;
				}
			} catch (SQLException e) {
				logger.error(e);
				return LoginType.notDBConnect;
			} finally {
				if(resultSet != null){
					try {
						resultSet.close();
					} catch (SQLException e) {
						logger.error(e);
					}
				}else{}
				if(pst != null){
					try {
						pst.close();
					} catch (SQLException e) {
						logger.error(e);
					}
				}else{}
				if(connection != null){
					try {
						connection.close();
					} catch (SQLException e) {
						logger.error(e);
					}
				}else{}
			}
		}
	}
	
	
	public static String encryptSHA256(String string) {

		try {
			MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");

			byte[] stringBytes = string.getBytes();
			int stringBytesLength = stringBytes.length;

			byte[] dataBytes = new byte[1024];
			for (int i = 0; i < stringBytesLength; i++) {
				dataBytes[i] = stringBytes[i];
			}

			messageDigest.update(dataBytes, 0, stringBytesLength);

			byte[] encrypted = messageDigest.digest();		


			// base64 인코딩
			byte[] base64Encoded = Base64.encodeBase64(encrypted);
			// 결과
			String result = new String(base64Encoded, CharEncoding.UTF_8);

			return result;
		}
		catch (Exception e) {

			return null;
		}
	}
	
	
	

	private void init(){
		try {
			
//			logger.debug("init start");
			
			FileInputStream iniIS = new FileInputStream(iniFilePath);
			Properties properties = new Properties();
			properties.load(iniIS);
			dbHost = properties.getProperty("db_host", "");
			dbPort = Integer.parseInt(properties.getProperty("db_port", "0"));
			dbUserName = properties.getProperty("db_user_name", "");
			dbUserPassword = properties.getProperty("db_user_password", "");
			dbName = properties.getProperty("db_name", "");
			sql = properties.getProperty("sql", "");
			isInit = true;
			
//			logger.debug("init end");
			
			
		} catch (FileNotFoundException e) {
			logger.error(e);
		} catch (IOException e) {
			logger.error(e);
		}
	}
}

//end123
