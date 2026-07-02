using System.Buffers;
using System.Collections;
using JetBrains.Annotations;

namespace FileEncrypter;

/// <summary>
/// A pooled array wrapper
/// </summary>
/// <param name="length">Length of the pooled array to create</param>
/// <typeparam name="T">Array element type</typeparam>
[PublicAPI]
public struct PooledArray<T>(int length) : IList<T>, IDisposable
{
    private bool isDisposed;
    private readonly T[] array = ArrayPool<T>.Shared.Rent(length);

    /// <inheritdoc cref="System.Array.Length"/>
    public int Length { get; } = length;

    /// <inheritdoc />
    /// <exception cref="ObjectDisposedException">If the pooled array has already been returned</exception>
    public T this[int index]
    {
        get => this.AsSpan[index];
        set => this.AsSpan[index] = value;
    }

    /// <inheritdoc cref="System.Span{T}.Item(System.Int32)"/>
    /// <exception cref="ObjectDisposedException">If the pooled array has already been returned</exception>
    public T this[Index index]
    {
        get => this.AsSpan[index];
        set => this.AsSpan[index] = value;
    }

    /// <summary>
    /// Forms a slice of the given array across the specified range
    /// </summary>
    /// <param name="range">Index range to get the slice for</param>
    /// <exception cref="ObjectDisposedException">If the pooled array has already been returned</exception>
    public Span<T> this[Range range] => this.AsSpan[range];

    /// <summary>
    /// Gets a span of the given pooled array
    /// </summary>
    /// <exception cref="ObjectDisposedException">If the pooled array has already been returned</exception>
    public Span<T> AsSpan
    {
        get
        {
            ObjectDisposedException.ThrowIf(this.isDisposed, GetType());
            return this.array.AsSpan(0, this.Length);
        }
    }

    /// <summary>
    /// Gets a memory block of the given pooled array
    /// </summary>
    /// <exception cref="ObjectDisposedException">If the pooled array has already been returned</exception>
    public Memory<T> AsMemory
    {
        get
        {
            ObjectDisposedException.ThrowIf(this.isDisposed, GetType());
            return this.array.AsMemory(0, this.Length);
        }
    }

    /// <summary>
    /// Gets the raw underlying array of this pooled array.<br/>
    /// </summary>
    /// <remarks><b>WARNING</b>: The length of the actual array may be larger than the requested length of the pooled array.</remarks>
    /// <exception cref="ObjectDisposedException">If the pooled array has already been returned</exception>
    public T[] AsRawArray
    {
        get
        {
            ObjectDisposedException.ThrowIf(this.isDisposed, GetType());
            return this.array;
        }
    }

    /// <summary>
    /// Gets a reference to the element at the specified zero-based index.
    /// </summary>
    /// <returns>A reference to the element at the specified index.</returns>
    /// <inheritdoc cref="Item(System.Int32)"/>
    public ref T GetRef(int index) => ref this.AsSpan[index];

    /// <inheritdoc cref="GetRef(System.Int32)"/>
    public ref T GetRef(Index index) => ref this.AsSpan[index];

    /// <inheritdoc />
    /// <exception cref="ObjectDisposedException">If the pooled array has already been returned</exception>
    public bool Contains(T item) => this.AsSpan.Contains(item);

    /// <inheritdoc />
    /// <exception cref="ObjectDisposedException">If the pooled array has already been returned</exception>
    public void CopyTo(T[] otherArray, int arrayIndex) => this.AsSpan.CopyTo(otherArray.AsSpan(arrayIndex));

    /// <inheritdoc />
    /// <exception cref="ObjectDisposedException">If the pooled array has already been returned</exception>
    public int IndexOf(T item) => this.AsSpan.IndexOf(item);

    /// <inheritdoc />
    /// <exception cref="ObjectDisposedException">If the pooled array has already been returned</exception>
    public void Clear() => this.AsSpan.Clear();

    /// <inheritdoc cref="IEnumerable{T}.GetEnumerator()" />
    /// <exception cref="ObjectDisposedException">If the pooled array has already been returned</exception>
    public Enumerator GetEnumerator()
    {
        ObjectDisposedException.ThrowIf(this.isDisposed, GetType());
        return new Enumerator(this);
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (this.isDisposed) return;

        this.isDisposed = true;
        ArrayPool<T>.Shared.Return(this.array);
    }

    int ICollection<T>.Count => this.array.Length;
    bool ICollection<T>.IsReadOnly => this.array.IsReadOnly;
    void ICollection<T>.Add(T item) => ((ICollection<T>)this.array).Add(item);
    bool ICollection<T>.Remove(T item) => ((ICollection<T>)this.array).Remove(item);
    void IList<T>.Insert(int index, T item) => ((IList<T>)this.array).Insert(index, item);
    void IList<T>.RemoveAt(int index) => ((IList<T>)this.array).RemoveAt(index);
    IEnumerator<T> IEnumerable<T>.GetEnumerator() => GetEnumerator();
    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

    public struct Enumerator(PooledArray<T> pooledArray) : IEnumerator<T>
    {
        private int index = -1;

        /// <inheritdoc />
        public T Current => pooledArray.AsSpan[this.index];

        /// <inheritdoc />
        public bool MoveNext() => ++this.index < pooledArray.Length;

        object? IEnumerator.Current => pooledArray.AsSpan[this.index];
        void IEnumerator.Reset() => this.index = -1;
        void IDisposable.Dispose() { }
    }
}
