//// EVOCertificateManager.PcscPoller
//using System;
//using System.Collections;
//using System.ComponentModel;
//using System.Threading;
//using EVOCertificateManager;

//public class PcscPoller
//{
//	public delegate void CallbackStatusChangeHandler();

//	private PcscContext _cardContext;

//	private PcscContext _deviceContext;

//	private BackgroundWorker _workerCards;

//	private BackgroundWorker _workerReaders;

//	private volatile bool _isCardStatusWaitingCancelled;

//	private volatile bool _isStopping;

//	private volatile bool _isPaused;

//	public int Infinite => -1;

//	public event CallbackStatusChangeHandler StatusChangeEventHandler;

//	public PcscPoller()
//	{
//		_cardContext = new PcscContext();
//		_deviceContext = new PcscContext();
//	}

//	private void PollCards()
//	{
//		_isCardStatusWaitingCancelled = false;
//		_workerCards = new BackgroundWorker();
//		_workerCards.WorkerSupportsCancellation = true;
//		_workerCards.DoWork += WaitForCardStatusChange;
//		_workerCards.RunWorkerCompleted += RunWorkerCardCompleted;
//		_workerCards.RunWorkerAsync();
//	}

//	private void PollDevices()
//	{
//		_isStopping = false;
//		_workerReaders = new BackgroundWorker();
//		_workerReaders.WorkerSupportsCancellation = true;
//		_workerReaders.DoWork += WaitForDeviceChange;
//		_workerReaders.RunWorkerAsync();
//	}

//	public void Poll()
//	{
//		_isPaused = false;
//		PollCards();
//		PollDevices();
//	}

//	~PcscPoller()
//	{
//		Stop();
//	}

//	public void Stop()
//	{
//		_isStopping = true;
//		_isCardStatusWaitingCancelled = true;
//		_isPaused = false;
//		CancelCardAndDeviceStatusWaiting();
//	}

//	public void Pause()
//	{
//		_isPaused = true;
//		CancelCardAndDeviceStatusWaiting();
//	}

//	public void Resume()
//	{
//		_isPaused = false;
//		if (!_workerCards.IsBusy)
//		{
//			_workerCards.RunWorkerAsync();
//			WaitForCardPollingBackgroundWorkerToStart();
//		}
//	}

//	public void WaitForDeviceChange(object sender, DoWorkEventArgs e)
//	{
//		try
//		{
//			_deviceContext.Establish();
//			PcscProvider.SCARD_READERSTATE[] array = new PcscProvider.SCARD_READERSTATE[1];
//			InitializeDeviceChangeReaderState(array);
//			int statusChange = _deviceContext.GetStatusChange(0, array);
//			if (statusChange != 0 && statusChange != -2146435026 && statusChange != -2146435062)
//			{
//				throw new PcscException(statusChange);
//			}
//			ResetReaderEventState(ref array[0]);
//			while (!e.Cancel)
//			{
//				WaitResumePolling();
//				if (_isStopping)
//				{
//					break;
//				}
//				statusChange = _deviceContext.GetStatusChange(Infinite, array);
//				switch (statusChange)
//				{
//				case -2146435070:
//					if (_isStopping)
//					{
//						return;
//					}
//					break;
//				case -2146435026:
//					Thread.Sleep(500);
//					break;
//				case -2146435043:
//				case -2146435042:
//					_deviceContext.Release();
//					_deviceContext.Establish();
//					break;
//				default:
//					throw new PcscException(statusChange);
//				case 0:
//					ResetReaderEventState(ref array[0]);
//					RestartCardPollingBackgroundWorker();
//					break;
//				case -2146435062:
//					break;
//				}
//			}
//		}
//		catch (PcscException)
//		{
//			_isPaused = false;
//			PollDevices();
//			throw;
//		}
//	}

//	private void WaitResumePolling()
//	{
//		while (_isPaused)
//		{
//			Thread.Sleep(0);
//		}
//	}

//	private void RestartCardPollingBackgroundWorker()
//	{
//		_isCardStatusWaitingCancelled = true;
//		CancelCardStatusWaiting();
//		if (_workerCards != null && _workerCards.IsBusy)
//		{
//			_workerCards.CancelAsync();
//		}
//		else if (_workerCards != null && !_workerCards.CancellationPending)
//		{
//			_workerCards.RunWorkerAsync();
//		}
//	}

//	private void WaitForCardPollingBackgroundWorkerToStart()
//	{
//		while (!_workerCards.IsBusy)
//		{
//			Thread.Sleep(0);
//		}
//	}

//	private void InitializeDeviceChangeReaderState(PcscProvider.SCARD_READERSTATE[] readerStates)
//	{
//		readerStates[0].szReader = "\\\\?PnP?\\Notification";
//		readerStates[0].pvUserData = IntPtr.Zero;
//		readerStates[0].cbAtr = 0;
//		readerStates[0].dwCurrentState = 0;
//		readerStates[0].dwEventState = 4;
//		readerStates[0].rgbAtr = null;
//	}

//	private void CancelCardAndDeviceStatusWaiting()
//	{
//		CancelCardStatusWaiting();
//		CancelDeviceStatusWaiting();
//	}

//	private void CancelDeviceStatusWaiting()
//	{
//		CancelStatusWaiting(ref _deviceContext);
//	}

//	private void CancelCardStatusWaiting()
//	{
//		try
//		{
//			CancelStatusWaiting(ref _cardContext);
//		}
//		catch (PcscException ex)
//		{
//			if (ex.ErrorCode == -2146435043 || ex.ErrorCode == -2146435042)
//			{
//				_cardContext.Release();
//				_cardContext.Establish();
//				return;
//			}
//			throw new PcscException(ex.ErrorCode);
//		}
//	}

//	private static void CancelStatusWaiting(ref PcscContext context)
//	{
//		context.Cancel();
//	}

//	public void WaitForCardStatusChange(object sender, DoWorkEventArgs e)
//	{
//		try
//		{
//			_cardContext.Establish();
//			int num = -2146435043;
//			int num2 = 100;
//			PcscProvider.SCARD_READERSTATE[] readerStates = null;
//			while (num != 0 && num2 > 0)
//			{
//				readerStates = GetInitialReaderStates();
//				num = _cardContext.GetStatusChange(0, readerStates);
//				num2--;
//			}
//			PcscProvider.SCARD_READERSTATE[] resetReaderStates = new PcscProvider.SCARD_READERSTATE[readerStates.Length];
//			if (num2 == 0)
//			{
//				throw new PcscException(num);
//			}
//			int[] previousStates = new int[readerStates.Length];
//			CopyReaderStates(readerStates, previousStates);
//			ResetReaderEventStates(ref readerStates);
//			try
//			{
//				RunStatusChangeEventHandler();
//			}
//			catch (Exception)
//			{
//				_isPaused = false;
//				PollCards();
//				return;
//			}
//			while (!e.Cancel)
//			{
//				WaitResumePolling();
//				if (_isStopping)
//				{
//					break;
//				}
//				num = _cardContext.GetStatusChange(Infinite, readerStates);
//				if (_workerCards.CancellationPending)
//				{
//					e.Cancel = true;
//					break;
//				}
//				switch (num)
//				{
//				case -2146435070:
//					break;
//				case -2146435043:
//				case -2146435042:
//					_cardContext.Release();
//					_cardContext.Establish();
//					continue;
//				default:
//					throw new PcscException(num);
//				case 0:
//					Array.Copy(readerStates, resetReaderStates, readerStates.Length);
//					ResetCardStatusChange(ref resetReaderStates);
//					CopyCurrentReaderStates(readerStates, previousStates);
//					ResetReaderEventStates(ref readerStates, resetReaderStates);
//					if (AreCurrentReaderStatesDifferent(resetReaderStates, previousStates))
//					{
//						try
//						{
//							RunStatusChangeEventHandler();
//						}
//						catch (Exception)
//						{
//							_isPaused = false;
//							PollCards();
//							return;
//						}
//					}
//					continue;
//				case -2146435062:
//					continue;
//				}
//				if (_isCardStatusWaitingCancelled)
//				{
//					break;
//				}
//			}
//			_isCardStatusWaitingCancelled = false;
//		}
//		catch (PcscException ex3)
//		{
//			if (ex3.ErrorCode != -2146435026)
//			{
//				_isPaused = false;
//				PollCards();
//				throw;
//			}
//		}
//	}

//	private void RunWorkerCardCompleted(object sender, RunWorkerCompletedEventArgs e)
//	{
//		if (e != null && e.Cancelled)
//		{
//			_workerCards.RunWorkerAsync();
//		}
//	}

//	private bool AreCurrentReaderStatesDifferent(PcscProvider.SCARD_READERSTATE[] readerStates, int[] previousStates)
//	{
//		bool result = false;
//		for (int i = 0; i < readerStates.Length; i++)
//		{
//			if (previousStates[i] != PcscProvider.GetStates(readerStates[i].dwEventState))
//			{
//				result = true;
//				break;
//			}
//		}
//		return result;
//	}

//	private static void CopyCurrentReaderStates(PcscProvider.SCARD_READERSTATE[] readerStates, int[] previousStates)
//	{
//		for (int i = 0; i < readerStates.Length; i++)
//		{
//			previousStates[i] = PcscProvider.GetStates(readerStates[i].dwCurrentState);
//		}
//	}

//	private static void CopyReaderStates(PcscProvider.SCARD_READERSTATE[] readerStates, int[] previousStates)
//	{
//		for (int i = 0; i < readerStates.Length; i++)
//		{
//			previousStates[i] = PcscProvider.GetStates(readerStates[i].dwEventState);
//		}
//	}

//	private void RunStatusChangeEventHandler()
//	{
//		if (this.StatusChangeEventHandler != null)
//		{
//			this.StatusChangeEventHandler();
//		}
//	}

//	private void ResetReaderEventStates(ref PcscProvider.SCARD_READERSTATE[] readerStates)
//	{
//		for (int i = 0; i < readerStates.Length; i++)
//		{
//			ResetReaderEventState(ref readerStates[i]);
//		}
//	}

//	private void ResetReaderEventStates(ref PcscProvider.SCARD_READERSTATE[] readerStates, PcscProvider.SCARD_READERSTATE[] newReaderStates)
//	{
//		for (int i = 0; i < readerStates.Length; i++)
//		{
//			readerStates[i].dwCurrentState = newReaderStates[i].dwEventState;
//			readerStates[i].dwEventState = 4;
//		}
//	}

//	private PcscProvider.SCARD_READERSTATE[] GetInitialReaderStates()
//	{
//		ArrayList allReaders = GetAllReaders();
//		PcscProvider.SCARD_READERSTATE[] array = new PcscProvider.SCARD_READERSTATE[allReaders.Count];
//		for (int i = 0; i < allReaders.Count; i++)
//		{
//			InitializeReaderStateForCardStatusChange(ref array[i], allReaders[i].ToString());
//		}
//		return array;
//	}

//	private static void ResetReaderEventState(ref PcscProvider.SCARD_READERSTATE readerState)
//	{
//		readerState.dwCurrentState = readerState.dwEventState;
//		readerState.dwEventState = 4;
//	}

//	private void InitializeReaderStateForCardStatusChange(ref PcscProvider.SCARD_READERSTATE readerState, string readername)
//	{
//		readerState.szReader = readername;
//		readerState.pvUserData = IntPtr.Zero;
//		readerState.cbAtr = 0;
//		readerState.dwCurrentState = 0;
//		readerState.dwEventState = 4;
//		readerState.rgbAtr = null;
//	}

//	public ArrayList GetAllReaders()
//	{
//		int size = 0;
//		ArrayList arrayList = new ArrayList();
//		int num = _deviceContext.ListReaders(null, ref size);
//		if (num != 0)
//		{
//			throw new PcscException(num);
//		}
//		string text = new string('\0', size);
//		num = _deviceContext.ListReaders(text, ref size);
//		if (num != 0)
//		{
//			throw new PcscException(num);
//		}
//		char[] trimChars = new char[1];
//		string text2 = text.TrimEnd(trimChars);
//		char[] separator = new char[1];
//		arrayList.AddRange(text2.Split(separator));
//		return arrayList;
//	}

//	private void ResetCardStatusChange(ref PcscProvider.SCARD_READERSTATE[] resetReaderStates)
//	{
//		for (int i = 0; i < resetReaderStates.Length; i++)
//		{
//			resetReaderStates[i].dwCurrentState = 0;
//			resetReaderStates[i].dwEventState = 4;
//		}
//		_cardContext.GetStatusChange(0, resetReaderStates);
//	}
//}
